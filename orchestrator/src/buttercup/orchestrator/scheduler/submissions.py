from dataclasses import field, dataclass
from functools import lru_cache
import logging
import base64
import uuid
import json
from nats.js.client import JetStreamContext
from typing import Callable, Iterator, List, Set, Tuple
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
import buttercup.common.node_local as node_local
from pathlib import Path
from buttercup.common.constants import ARCHITECTURE
from buttercup.common.nats_queues import NatsQueue, NatsQueueFactory, QueueNames
from buttercup.common.nats_datastructures import NatsPoVReproduceStatus
from buttercup.common.datastructures.msg_pb2 import (
    TracedCrash,
    ConfirmedVulnerability,
    SubmissionEntry,
    SubmissionEntryPatch,
    BuildRequest,
    BuildType,
    BuildOutput,
    POVReproduceRequest,
    POVReproduceResponse,
    CrashWithId,
    Bundle,
    SubmissionResult,
    Patch,
)
from buttercup.common.nats_datastructures import NatsSARIFStore, SARIFBroadcastDetail
from buttercup.common.nats_datastructures import NatsTaskRegistry as TaskRegistry
from buttercup.common.telemetry import set_crs_attributes, CRSActionCategory

from buttercup.orchestrator.scheduler.sarif_matcher import match
from buttercup.orchestrator.competition_api_client.models.types_architecture import TypesArchitecture
from buttercup.orchestrator.competition_api_client.models.types_pov_submission import TypesPOVSubmission
from buttercup.orchestrator.competition_api_client.models.types_patch_submission import TypesPatchSubmission
from buttercup.orchestrator.competition_api_client.models.types_bundle_submission import TypesBundleSubmission
from buttercup.orchestrator.competition_api_client.models.types_submission_status import TypesSubmissionStatus
from buttercup.orchestrator.competition_api_client.models.types_sarif_assessment_submission import (
    TypesSarifAssessmentSubmission,
)
from buttercup.orchestrator.competition_api_client.models.types_assessment import TypesAssessment
from buttercup.orchestrator.competition_api_client.api_client import ApiClient
from buttercup.orchestrator.competition_api_client.api import PovApi, PatchApi, BundleApi, BroadcastSarifAssessmentApi
from buttercup.common.challenge_task import ChallengeTask
from buttercup.common.project_yaml import ProjectYaml
from buttercup.common.stack_parsing import get_crash_data, get_inst_key
from buttercup.common.clusterfuzz_parser.crash_comparer import CrashComparer

logger = logging.getLogger(__name__)


def _map_submission_status_to_result(status: TypesSubmissionStatus) -> SubmissionResult:
    """Map TypesSubmissionStatus to SubmissionResult enum."""
    mapping = {
        TypesSubmissionStatus.SubmissionStatusAccepted: SubmissionResult.ACCEPTED,
        TypesSubmissionStatus.SubmissionStatusPassed: SubmissionResult.PASSED,
        TypesSubmissionStatus.SubmissionStatusFailed: SubmissionResult.FAILED,
        TypesSubmissionStatus.SubmissionStatusDeadlineExceeded: SubmissionResult.DEADLINE_EXCEEDED,
        TypesSubmissionStatus.SubmissionStatusErrored: SubmissionResult.ERRORED,
        TypesSubmissionStatus.SubmissionStatusInconclusive: SubmissionResult.INCONCLUSIVE,
    }
    return mapping.get(status, SubmissionResult.ERRORED)  # Default to ERRORED for unknown statuses


def _task_id(e: SubmissionEntry | TracedCrash) -> str:
    """Get the task_id from the SubmissionEntry or TracedCrash."""
    if isinstance(e, TracedCrash):
        return e.crash.target.task_id  # type: ignore[no-any-return]
    elif isinstance(e, SubmissionEntry):
        return e.crashes[0].crash.crash.target.task_id  # type: ignore[no-any-return]
    else:
        raise ValueError(f"Unknown submission entry type: {type(e)}")


def log_entry(
    e: SubmissionEntry,
    msg: str = "",
    i: int | None = None,
    fn: Callable[[str], None] = logger.info,
) -> None:
    """Log a structured message for easy grepping and filtering."""
    task_id = _task_id(e)
    idx_msg = f"{i}:" if i is not None else ""

    log_msg = f"[{idx_msg}{task_id}]"

    def _truncate_join(items: list[str], max_length: int = 256) -> str:
        """Join list items with commas, truncating if the result exceeds max_length."""
        joined = ",".join(items)
        if len(joined) <= max_length:
            return joined
        # Truncate and add ellipsis
        return joined[: max_length - 3] + "..."

    competition_pov_ids = [c.competition_pov_id for c in e.crashes if c.competition_pov_id]
    if competition_pov_ids:
        log_msg += f" pov_id={_truncate_join(competition_pov_ids)}"

    if len(e.patches) > 0:
        log_msg += f" patches={len(e.patches)}"

    if e.patch_idx:
        log_msg += f" patch_idx={e.patch_idx}"

    if e.patch_submission_attempts:
        log_msg += f" patch_submission_attempts={e.patch_submission_attempts}"

    competition_patch_ids = [p.competition_patch_id for p in e.patches if p.competition_patch_id]
    if competition_patch_ids:
        log_msg += f" competition_patch_id={_truncate_join(competition_patch_ids)}"

    competition_bundle_ids = [b.bundle_id for b in e.bundles if b.bundle_id]
    if competition_bundle_ids:
        log_msg += f" bundle_id={_truncate_join(competition_bundle_ids)}"

    sarif_ids = [b.competition_sarif_id for b in e.bundles if b.competition_sarif_id]
    if sarif_ids:
        log_msg += f" sarif_id={_truncate_join(sarif_ids)}"

    if msg:
        log_msg += f" {msg}"

    fn(log_msg)


def _advance_patch_idx(e: SubmissionEntry) -> None:
    """Advance the patch index to the next patch."""
    e.patch_idx += 1
    e.patch_submission_attempts = 0


def _increase_submission_attempts(e: SubmissionEntry) -> None:
    """Increase the submission attempts for the current patch."""
    e.patch_submission_attempts += 1


def _current_patch(e: SubmissionEntry) -> SubmissionEntryPatch | None:
    """Get the current patch."""
    if not e.patches:
        return None
    if e.patch_idx >= len(e.patches):
        return None
    return e.patches[e.patch_idx]


def _get_pending_patch_submissions(e: SubmissionEntry) -> list[SubmissionEntryPatch]:
    """Get all pending patch submissions from the submission entry.
    It is considered pending if it has a competition_patch_id and is in the ACCEPTED state.
    """
    return [patch for patch in e.patches if patch.competition_patch_id and patch.result == SubmissionResult.ACCEPTED]


def _get_first_successful_pov(e: SubmissionEntry) -> CrashWithId | None:
    """Get the first successful POV from the submission entry.

    Returns None if no successful POV is found.
    """
    return next(
        (crash for crash in e.crashes if crash.competition_pov_id and crash.result == SubmissionResult.PASSED),
        None,
    )


def _get_pending_pov_submissions(e: SubmissionEntry) -> list[CrashWithId]:
    """Get all pending POVs from the submission entry.
    It is considered pending if the POV is accepted but not yet passed.

    Returns None if no pending POV is found.
    """
    return [crash for crash in e.crashes if crash.competition_pov_id and crash.result == SubmissionResult.ACCEPTED]


def _get_first_successful_pov_id(e: SubmissionEntry) -> str | None:
    """Get the first successful POV ID from the submission entry.

    Returns None if no successful POV is found.
    """
    pov = _get_first_successful_pov(e)
    if pov:
        return pov.competition_pov_id  # type: ignore[no-any-return]
    return None


def _get_eligible_povs_for_submission(e: SubmissionEntry) -> list[CrashWithId]:
    """Get all POVs that are eligible for submission.

    A POV is eligible for submission if:
    - It doesn't have a competition_pov_id, or
    - It has a competition_pov_id but is in ERRORED state (can be retried)

    Returns:
        List of CrashWithId objects that are eligible for submission
    """
    return [
        crash
        for crash in e.crashes
        if not crash.competition_pov_id or (crash.competition_pov_id and crash.result == SubmissionResult.ERRORED)
    ]


def _find_matching_build_output(patch: SubmissionEntryPatch, build_output: BuildOutput) -> BuildOutput | None:
    """Find the matching build output in the patch."""
    # Found the patch, now locate the placeholder for the build output
    return next(
        (
            bo
            for bo in patch.build_outputs
            if (
                bo.engine == build_output.engine
                and bo.sanitizer == build_output.sanitizer
                and bo.build_type == build_output.build_type
                and bo.apply_diff == build_output.apply_diff
            )
        ),
        None,
    )


class CompetitionAPI:
    """
    Simplified interface for the competition API.
    """

    def __init__(self, api_client: ApiClient, task_registry: TaskRegistry) -> None:
        self.api_client = api_client
        self.task_registry = task_registry

    @lru_cache(maxsize=10)
    async def _get_task_metadata(self, task_id: str) -> dict:
        task = await self.task_registry.get(task_id)
        return dict(task.metadata) if task else {}

    async def submit_pov(self, crash: TracedCrash) -> Tuple[str | None, SubmissionResult]:
        try:
            with node_local.lopen(crash.crash.crash_input_path, "rb") as f:
                crash_data = base64.b64encode(f.read()).decode()

            submission = TypesPOVSubmission(
                architecture=TypesArchitecture(ARCHITECTURE),
                engine=crash.crash.target.engine,
                fuzzer_name=crash.crash.harness_name,
                sanitizer=crash.crash.target.sanitizer,
                testcase=crash_data,
            )

            tracer = trace.get_tracer(__name__)
            with tracer.start_as_current_span("submit_pov_for_scoring") as span:
                set_crs_attributes(
                    span,
                    crs_action_category=CRSActionCategory.SCORING_SUBMISSION,
                    crs_action_name="submit_pov_for_scoring",
                    task_metadata=await self._get_task_metadata(_task_id(crash)),
                    extra_attributes={
                        "crs.action.target.harness": crash.crash.harness_name,
                    },
                )

                logger.debug(f"[{crash.crash.target.task_id}] Submitting POV for harness: {crash.crash.harness_name}")

                response = await PovApi(api_client=self.api_client).v1_task_task_id_pov_post(
                    task_id=crash.crash.target.task_id,
                    payload=submission,
                )
                logger.debug(f"[{crash.crash.target.task_id}] POV submission response: {response}")
                mapped_status = _map_submission_status_to_result(response.status)
                if mapped_status not in [
                    SubmissionResult.ACCEPTED,
                    SubmissionResult.PASSED,
                ]:
                    logger.error(
                        f"[{crash.crash.target.task_id}] POV submission rejected (status: {response.status}) for harness: {crash.crash.harness_name}"
                    )
                    span.set_status(Status(StatusCode.ERROR))
                    return None, mapped_status

                span.set_status(Status(StatusCode.OK))
                return response.pov_id, mapped_status
        except Exception as e:
            logger.error(f"[{crash.crash.target.task_id}] Failed to submit vulnerability: {e}")
            return None, SubmissionResult.ERRORED

    async def get_pov_status(self, task_id: str, pov_id: str) -> SubmissionResult:
        assert task_id
        assert pov_id

        response = await PovApi(api_client=self.api_client).v1_task_task_id_pov_pov_id_get(
            task_id=task_id, pov_id=pov_id
        )
        return _map_submission_status_to_result(response.status)

    async def submit_patch(self, task_id: str, patch: str) -> Tuple[str | None, SubmissionResult]:
        assert task_id
        assert patch

        encoded_patch = base64.b64encode(patch.encode()).decode()
        submission = TypesPatchSubmission(
            patch=encoded_patch,
        )

        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span("submit_patch_for_scoring") as span:
            set_crs_attributes(
                span,
                crs_action_category=CRSActionCategory.SCORING_SUBMISSION,
                crs_action_name="submit_patch_for_scoring",
                task_metadata=await self._get_task_metadata(task_id),
            )

            logger.debug(f"[{task_id}] Submitting patch")

            response = await PatchApi(api_client=self.api_client).v1_task_task_id_patch_post(
                task_id=task_id, payload=submission
            )
            logger.debug(f"[{task_id}] Patch submission response: {response}")
            mapped_status = _map_submission_status_to_result(response.status)
            if mapped_status not in [
                SubmissionResult.ACCEPTED,
                SubmissionResult.PASSED,
            ]:
                logger.error(f"[{task_id}] Patch submission rejected (status: {response.status}) for harness: {patch}")
                span.set_status(Status(StatusCode.ERROR))
                return (None, mapped_status)

            span.set_status(Status(StatusCode.OK))
            return (response.patch_id, mapped_status)

    async def get_patch_status(self, task_id: str, patch_id: str) -> SubmissionResult:
        assert task_id
        assert patch_id

        response = await PatchApi(api_client=self.api_client).v1_task_task_id_patch_patch_id_get(
            task_id=task_id, patch_id=patch_id
        )
        if response.functionality_tests_passing is not None:
            logger.info(
                f"[{task_id}] Patch {patch_id} functionality tests passing: {response.functionality_tests_passing}"
            )
        return _map_submission_status_to_result(response.status)

    async def submit_bundle(
        self, task_id: str, pov_id: str, patch_id: str, sarif_id: str
    ) -> Tuple[str | None, SubmissionResult]:
        assert task_id
        assert pov_id

        submission = TypesBundleSubmission(
            pov_id=pov_id,
        )
        if sarif_id:
            submission.broadcast_sarif_id = sarif_id
        if patch_id:
            submission.patch_id = patch_id

        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span("submit_bundle_for_scoring") as span:
            set_crs_attributes(
                span,
                crs_action_category=CRSActionCategory.SCORING_SUBMISSION,
                crs_action_name="submit_bundle_for_scoring",
                task_metadata=await self._get_task_metadata(task_id),
            )

            logger.debug(f"[{task_id}] Submitting bundle for harness: {pov_id} {patch_id} {sarif_id}")

            response = await BundleApi(api_client=self.api_client).v1_task_task_id_bundle_post(
                task_id=task_id, payload=submission
            )
            logger.debug(f"[{task_id}] Bundle submission response: {response}")
            mapped_status = _map_submission_status_to_result(response.status)
            if mapped_status not in [
                SubmissionResult.ACCEPTED,
                SubmissionResult.PASSED,
            ]:
                logger.error(f"[{task_id}] Bundle submission rejected (status: {response.status})")
                span.set_status(Status(StatusCode.ERROR))
                return (None, mapped_status)

            span.set_status(Status(StatusCode.OK))
            return (response.bundle_id, mapped_status)

    async def patch_bundle(
        self, task_id: str, bundle_id: str, pov_id: str, patch_id: str, sarif_id: str
    ) -> Tuple[bool, SubmissionResult]:
        assert task_id
        assert bundle_id
        assert pov_id
        assert patch_id
        assert sarif_id

        submission = TypesBundleSubmission(
            bundle_id=bundle_id,
            pov_id=pov_id,
            patch_id=patch_id,
            broadcast_sarif_id=sarif_id,
        )
        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span("patch_bundle") as span:
            set_crs_attributes(
                span,
                crs_action_category=CRSActionCategory.SCORING_SUBMISSION,
                crs_action_name="patch_bundle",
                task_metadata=await self._get_task_metadata(task_id),
            )
            response = await BundleApi(api_client=self.api_client).v1_task_task_id_bundle_bundle_id_patch(
                task_id=task_id, bundle_id=bundle_id, payload=submission
            )
            logger.debug(f"[{task_id}] Bundle patch submission response: {response}")
            mapped_status = _map_submission_status_to_result(response.status)
            if mapped_status not in [
                SubmissionResult.ACCEPTED,
                SubmissionResult.PASSED,
            ]:
                logger.error(
                    f"[{task_id}] Bundle patch submission rejected (status: {response.status}) for harness: {pov_id} {patch_id} {sarif_id}"
                )
                span.set_status(Status(StatusCode.ERROR))
                return (False, mapped_status)

            span.set_status(Status(StatusCode.OK))
            return (True, mapped_status)

    async def delete_bundle(self, task_id: str, bundle_id: str) -> bool:
        assert task_id
        assert bundle_id

        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span("delete_bundle") as span:
            set_crs_attributes(
                span,
                crs_action_category=CRSActionCategory.SCORING_SUBMISSION,
                crs_action_name="delete_bundle",
                task_metadata=await self._get_task_metadata(task_id),
            )

            try:
                logger.debug(f"[{task_id}] Deleting bundle: {bundle_id}")
                response = await BundleApi(api_client=self.api_client).v1_task_task_id_bundle_bundle_id_delete(
                    task_id=task_id, bundle_id=bundle_id
                )
                logger.debug(f"[{task_id}] Bundle deletion response: {response}")
                span.set_status(Status(StatusCode.OK))
                return True

            except Exception as e:
                logger.error(f"[{task_id}] Bundle deletion failed for bundle_id: {bundle_id}, error: {e}")
                span.set_status(Status(StatusCode.ERROR))
                return False

    async def submit_matching_sarif(self, task_id: str, sarif_id: str) -> Tuple[bool, SubmissionResult]:
        assert task_id
        assert sarif_id

        submission = TypesSarifAssessmentSubmission(
            assessment=TypesAssessment.AssessmentCorrect,
            description="Overlapping with our POV/patch",
        )

        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span("submit_SARIF_for_scoring") as span:
            set_crs_attributes(
                span,
                crs_action_category=CRSActionCategory.SCORING_SUBMISSION,
                crs_action_name="submit_SARIF_for_scoring",
                task_metadata=await self._get_task_metadata(task_id),
            )

            response = await BroadcastSarifAssessmentApi(
                api_client=self.api_client
            ).v1_task_task_id_broadcast_sarif_assessment_broadcast_sarif_id_post(
                task_id=task_id, broadcast_sarif_id=sarif_id, payload=submission
            )
            logger.debug(f"[{task_id}] Matching SARIF submission response: {response}")
            mapped_status = _map_submission_status_to_result(response.status)
            if mapped_status not in [
                SubmissionResult.ACCEPTED,
                SubmissionResult.PASSED,
            ]:
                logger.error(
                    f"[{task_id}] Matching SARIF submission rejected (status: {response.status}) for sarif_id: {sarif_id}"
                )
                span.set_status(Status(StatusCode.ERROR))
                return (False, mapped_status)

            span.set_status(Status(StatusCode.OK))
            return (True, mapped_status)


@dataclass
class NatsSubmissions:
    """
    Manages the complete lifecycle of vulnerability submissions to the competition API.
    """

    # NATS bucket names
    SUBMISSIONS_BUCKET = "submissions"
    MATCHED_SARIFS_BUCKET = "matched_sarifs"

    jetstream: JetStreamContext
    competition_api: CompetitionAPI
    task_registry: TaskRegistry
    tasks_storage_dir: Path
    patch_submission_retry_limit: int = 60
    patch_requests_per_vulnerability: int = 1
    concurrent_patch_requests_per_task: int = 12
    entries: List[SubmissionEntry] = field(init=False)
    sarif_store: NatsSARIFStore = field(init=False)
    matched_sarifs: Set[str] = field(default_factory=set)
    build_requests_queue: NatsQueue[BuildRequest] = field(init=False)
    pov_reproduce_status: NatsPoVReproduceStatus = field(init=False)

    async def __post_init__(self) -> None:
        logger.info(
            f"Initializing Submissions, patch_submission_retry_limit={self.patch_submission_retry_limit}, patch_requests_per_vulnerability={self.patch_requests_per_vulnerability}, concurrent_patch_requests_per_task={self.concurrent_patch_requests_per_task}"
        )
        self.entries = await self._get_stored_submissions()
        self.sarif_store = NatsSARIFStore(self.jetstream)
        self.matched_sarifs = await self._get_matched_sarifs()
        queue_factory = NatsQueueFactory(self.jetstream.client, self.jetstream)
        self.build_requests_queue = queue_factory.create(QueueNames.BUILD)
        await self.build_requests_queue.__post_init__()
        self.pov_reproduce_status = NatsPoVReproduceStatus(self.jetstream)

    async def _insert_matched_sarif(self, sarif_id: str) -> None:
        """Insert a matched SARIF ID into the KV store."""
        self.matched_sarifs.add(sarif_id)
        store = await self.jetstream.key_value(self.MATCHED_SARIFS_BUCKET)
        await store.put(sarif_id, b"1")

    async def _get_matched_sarifs(self) -> Set[str]:
        """Get all matched SARIF IDs from the KV store."""
        try:
            store = await self.jetstream.key_value(self.MATCHED_SARIFS_BUCKET)
            keys = await store.keys()
            return set(keys)
        except Exception:
            return set()

    async def _get_stored_submissions(self) -> List[SubmissionEntry]:
        """Get all stored submissions from the KV store."""
        try:
            store = await self.jetstream.key_value(self.SUBMISSIONS_BUCKET)
            entry = await store.get("submissions")
            if entry and entry.value:
                submissions_data = json.loads(entry.value)
                return [SubmissionEntry.FromString(bytes.fromhex(s)) for s in submissions_data]
            return []
        except Exception:
            return []

    async def _persist(self) -> None:
        """Persist the submissions to the KV store."""
        store = await self.jetstream.key_value(self.SUBMISSIONS_BUCKET)
        submissions_data = [s.SerializeToString().hex() for s in self.entries]
        await store.put("submissions", json.dumps(submissions_data).encode())

    async def _push(self, entry: SubmissionEntry) -> None:
        """Push a submission to the KV store."""
        self.entries.append(entry)
        await self._persist()

    async def _enumerate_submissions(self) -> Iterator[tuple[int, SubmissionEntry]]:
        """Enumerate all submissions belonging to active tasks."""
        for i, e in enumerate(self.entries):
            if e.stop:
                continue
            if await self.task_registry.should_stop_processing(_task_id(e)):
                continue
            yield i, e

    async def _enumerate_task_submissions(self, task_id: str) -> Iterator[tuple[int, SubmissionEntry]]:
        """Enumerate all submissions belonging to a specific task (if it is active)."""
        async for i, e in self._enumerate_submissions():
            if _task_id(e) != task_id:
                continue
            yield i, e

    async def _find_patch(self, internal_patch_id: str) -> Tuple[int, SubmissionEntry, SubmissionEntryPatch] | None:
        """Find a patch by its internal patch id."""
        async for i, e in self._enumerate_submissions():
            for patch in e.patches:
                if patch.internal_patch_id == internal_patch_id:
                    return i, e, patch
        return None

    async def find_similar_entries(self, crash: TracedCrash) -> list[tuple[int, SubmissionEntry]]:
        """
        Find existing submissions that have crashes similar to the given crash.
        """
        crash_data = get_crash_data(crash.crash.stacktrace)
        inst_key = get_inst_key(crash.crash.stacktrace)
        task_id = _task_id(crash)

        similar_entries = []
        async for i, e in self._enumerate_task_submissions(task_id):
            for existing_crash_with_id in e.crashes:
                submission_crash_data = get_crash_data(existing_crash_with_id.crash.crash.stacktrace)
                submission_inst_key = get_inst_key(existing_crash_with_id.crash.crash.stacktrace)

                cf_comparator = CrashComparer(crash_data, submission_crash_data)
                instkey_comparator = CrashComparer(inst_key, submission_inst_key)

                if cf_comparator.is_similar() or instkey_comparator.is_similar():
                    log_entry(
                        e,
                        f"Incoming PoV crash_data: {crash_data}, inst_key: {inst_key}, existing crash_data: {submission_crash_data}, existing inst_key: {submission_inst_key} are duplicates. ",
                        i,
                        fn=logger.debug,
                    )

                    similar_entries.append((i, e))
                    break

        return similar_entries

    async def _add_to_similar_submission(self, crash: TracedCrash) -> bool:
        """
        Check if the crash is similar to an existing submission and add it if so.
        """
        similar_entries = await self.find_similar_entries(crash)

        if len(similar_entries) == 0:
            return False
        else:
            await self._consolidate_similar_submissions(crash, similar_entries)
            return True

    async def _consolidate_similar_submissions(
        self, crash: TracedCrash | None, similar_entries: list[tuple[int, SubmissionEntry]]
    ) -> None:
        """
        Consolidate multiple similar submissions into the first one.
        """
        target_index, target_entry = similar_entries[0]

        if crash is not None:
            crash_with_id = CrashWithId()
            crash_with_id.crash.CopyFrom(crash)
            target_entry.crashes.append(crash_with_id)

        log_entry(
            target_entry,
            i=target_index,
            msg=f"Consolidating {len(similar_entries)} similar submissions into this one. Adding new crash."
            if crash is not None
            else f"Consolidating {len(similar_entries)} similar submissions into this one.",
        )

        for source_index, source_entry in similar_entries[1:]:
            log_entry(source_entry, i=source_index, msg=f"Merging submission into target at index {target_index}")

            target_entry.crashes.extend(source_entry.crashes)

            if source_entry.patch_idx < len(source_entry.patches):
                target_entry.patches.extend(source_entry.patches[source_entry.patch_idx :])

            target_entry.bundles.extend(source_entry.bundles)

            source_entry.stop = True

            log_entry(
                source_entry,
                i=source_index,
                msg=f"Submission consolidated and stopped. Total crashes in target: {len(target_entry.crashes)}, total patches: {len(target_entry.patches)}",
            )

        self._reorder_patches_by_completion(target_entry)

        await self._persist()

        log_entry(
            target_entry,
            i=target_index,
            msg=f"Consolidation complete. Final submission has {len(target_entry.crashes)} crashes and {len(target_entry.patches)} patches.",
        )

    async def submit_vulnerability(self, crash: TracedCrash) -> bool:
        """
        Entry point for new vulnerability discoveries from fuzzers.
        """
        if await self.task_registry.should_stop_processing(_task_id(crash)):
            logger.info("Task is cancelled or expired, will not submit vulnerability.")
            logger.debug(f"CrashInfo: {crash}")
            return True

        if await self._add_to_similar_submission(crash):
            return True

        e = SubmissionEntry()
        crash_with_id = CrashWithId()
        crash_with_id.crash.CopyFrom(crash)
        e.crashes.append(crash_with_id)

        await self._push(e)

        log_entry(e, msg="Recorded unique PoV")
        return True

    async def _submit_pov_if_needed(self, i: int, e: SubmissionEntry) -> bool:
        """
        Submit first eligible POV to competition API if none are pending/successful.
        """
        if _get_first_successful_pov(e):
            return False

        if _get_pending_pov_submissions(e):
            return False

        for pov in _get_eligible_povs_for_submission(e):
            pov_id, status = await self.competition_api.submit_pov(pov.crash)
            if pov_id:
                pov.competition_pov_id = pov_id
                pov.result = status
                log_entry(e, i=i, msg="Submitted POV")
                return True
            else:
                logger.error(
                    f"[{_task_id(pov.crash)}] Failed to submit vulnerability. Competition API returned {status}. Will attempt the next PoV."
                )
                logger.debug(f"CrashInfo: {pov.crash}")
                log_entry(e, i=i, msg="Failed to submit POV")

        return False

    async def _update_pov_status(self, i: int, e: SubmissionEntry) -> bool:
        """
        Poll competition API for status updates on pending POVs.
        """
        updated = False
        for pov in _get_pending_pov_submissions(e):
            status = await self.competition_api.get_pov_status(_task_id(pov.crash), pov.competition_pov_id)
            if status != SubmissionResult.ACCEPTED:
                pov.result = status
                log_entry(e, i=i, msg=f"Updated POV status. New status {SubmissionResult.Name(status)}")
                updated = True
        return updated

    async def _task_outstanding_patch_requests(self, task_id: str) -> int:
        """
        Check the number of patch requests that have not been completed for the given task.
        """
        n = 0
        async for _, e in self._enumerate_task_submissions(task_id):
            maybe_patch = _current_patch(e)
            if maybe_patch and not maybe_patch.patch:
                n += 1
        return n

    async def _request_patch_if_needed(self, i: int, e: SubmissionEntry) -> bool:
        """
        Request patch generation via queue if no current patch and conditions are met.
        """
        if _current_patch(e):
            return False

        if await self._should_wait_for_patch_mitigation_merge(i, e):
            return False

        if await self._task_outstanding_patch_requests(_task_id(e)) >= self.concurrent_patch_requests_per_task:
            log_entry(
                e,
                i=i,
                msg=f"Skipping patch request because there are already {await self._task_outstanding_patch_requests(_task_id(e))} outstanding patch requests for the task",
                fn=logger.debug,
            )
            return False

        log_entry(e, i=i, msg="Submitting patch request")

        patch_tracker = self._new_patch_tracker()
        confirmed = ConfirmedVulnerability()
        for crash_with_id in e.crashes:
            confirmed.crashes.append(crash_with_id.crash)
        confirmed.internal_patch_id = patch_tracker.internal_patch_id
        e.patches.append(patch_tracker)

        q = NatsQueueFactory(self.jetstream.client, self.jetstream).create(QueueNames.CONFIRMED_VULNERABILITIES)
        await q.__post_init__()
        await self._enqueue_patch_requests(confirmed_vulnerability=confirmed, q=q)

        log_entry(e, i=i, msg="Patch request submitted")

        return True

    async def _request_patched_builds_if_needed(self, i: int, e: SubmissionEntry) -> bool:
        """
        Make sure that builds are available for the current patch, if any.
        """
        patch = _current_patch(e)
        if not patch or not patch.patch or patch.build_outputs:
            return False

        task_id = _task_id(e)
        task = ChallengeTask(read_only_task_dir=self.tasks_storage_dir / task_id)
        project_yaml = ProjectYaml(task, task.task_meta.project_name)
        engine = "libfuzzer"
        if engine not in project_yaml.fuzzing_engines:
            engine = project_yaml.fuzzing_engines[0]
        sanitizers = project_yaml.sanitizers
        q = NatsQueueFactory(self.jetstream.client, self.jetstream).create(QueueNames.BUILD)
        await q.__post_init__()
        for san in sanitizers:
            build_output = BuildOutput(
                engine=engine,
                sanitizer=san,
                task_dir="",
                task_id=task_id,
                build_type=BuildType.PATCH,
                apply_diff=True,
                internal_patch_id=patch.internal_patch_id,
            )
            build_req = BuildRequest(
                engine=build_output.engine,
                task_dir=str(task.task_dir),
                task_id=build_output.task_id,
                build_type=build_output.build_type,
                sanitizer=build_output.sanitizer,
                apply_diff=build_output.apply_diff,
                patch=patch.patch,
                internal_patch_id=build_output.internal_patch_id,
            )
            await q.push(build_req)
            patch.build_outputs.append(build_output)
            logger.info(
                f"[{task_id}] Pushed build request {BuildType.Name(build_req.build_type)} | {build_req.sanitizer} | {build_req.engine} | {build_req.apply_diff} | {build_req.internal_patch_id}"
            )
        return True

    async def record_patched_build(self, build_output: BuildOutput) -> bool:
        """
        Entry point for completed patched builds from build system.
        """
        key = build_output.internal_patch_id
        maybe_patch = await self._find_patch(key)
        if not maybe_patch:
            logger.error(
                f"Build output {build_output.internal_patch_id} not found in any patch (task expired/cancelled?). Will discard."
            )
            return True

        i, e, patch = maybe_patch
        bo = _find_matching_build_output(patch, build_output)
        if not bo:
            logger.error(
                f"Build output {build_output.internal_patch_id} not found in patch {patch.internal_patch_id}. Will discard."
            )
            return True

        if bo.task_dir:
            logger.warning(
                f"Build output {build_output.internal_patch_id} already recorded for patch {patch.internal_patch_id}. Will discard."
            )
            return True

        if bo.task_id != build_output.task_id:
            logger.error(
                f"Build output {build_output.internal_patch_id} has a different task id than the patch. Will discard."
            )
            return True

        bo.task_dir = build_output.task_dir
        await self._persist()
        log_entry(e, i=i, msg=f"Patched build recorded for patch {patch.internal_patch_id}")
        return True

    async def _submit_patch_if_good(self, i: int, e: SubmissionEntry) -> bool:
        """
        Test current patch effectiveness and submit to competition API if it mitigates all POVs.
        """
        if not _get_first_successful_pov_id(e):
            return False

        patch = _current_patch(e)
        if not patch or not patch.patch:
            return False

        status = await self._check_all_povs_are_mitigated(i, e, e.patch_idx)
        if status is None:
            return False
        if not status:
            _advance_patch_idx(e)
            return True

        if patch.competition_patch_id:
            return False

        if await self._should_wait_for_patch_mitigation_merge(i, e):
            return False

        if e.patch_submission_attempts >= self.patch_submission_retry_limit:
            _advance_patch_idx(e)
            return True

        competition_patch_id, status = await self.competition_api.submit_patch(_task_id(e), patch.patch)
        patch.result = status
        if competition_patch_id:
            patch.competition_patch_id = competition_patch_id
            log_entry(e, i=i, msg=f"Patch successfully submitted id={competition_patch_id}")
        elif status == SubmissionResult.ERRORED:
            _increase_submission_attempts(e)
            log_entry(e, i=i, msg=f"Patch submission errored, will try again. Attempts={e.patch_submission_attempts}")
        elif status == SubmissionResult.FAILED or status == SubmissionResult.INCONCLUSIVE:
            _advance_patch_idx(e)
            log_entry(
                e, i=i, msg=f"Patch submission failed, advancing to next patch. Attempts={e.patch_submission_attempts}"
            )
        else:
            log_entry(e, i=i, msg=f"Patch submission returned unknown status {status}")

        return True

    async def _update_patch_status(self, i: int, e: SubmissionEntry) -> bool:
        """
        Update the status of any patch in the ACCEPTED state.
        """
        updated = False
        for patch in _get_pending_patch_submissions(e):
            status = await self.competition_api.get_patch_status(_task_id(e), patch.competition_patch_id)
            patch.result = status
            if status != SubmissionResult.ACCEPTED:
                updated = True
                if status in [SubmissionResult.FAILED, SubmissionResult.INCONCLUSIVE]:
                    _advance_patch_idx(e)
                elif status == SubmissionResult.ERRORED:
                    patch.competition_patch_id = None
                    _increase_submission_attempts(e)
                elif status == SubmissionResult.DEADLINE_EXCEEDED:
                    patch.competition_patch_id = None
                log_entry(e, i=i, msg=f"Patch status updated to {status.Name}")
        return updated

    async def _ensure_single_bundle(self, i: int, e: SubmissionEntry) -> bool:
        """
        When SubmissionEntries are merged, we might end up with multiple bundles.
        """
        if len(e.bundles) <= 1:
            return False

        last_bundle_id = e.bundles[-1].bundle_id
        task_id = _task_id(e)
        logger.debug(f"[{task_id}] Deleting bundle {last_bundle_id}")
        if await self.competition_api.delete_bundle(task_id, last_bundle_id):
            log_entry(e, i=i, msg=f"Deleted bundle {last_bundle_id}")
            e.bundles.pop()
            return True

        log_entry(e, i=i, msg=f"Failed to delete bundle {last_bundle_id}. Will keep trying.")
        return False

    async def _ensure_bundle_contents(
        self,
        i: int,
        e: SubmissionEntry,
        competition_pov_id: str,
        competition_patch_id: str | None = None,
        competition_sarif_id: str | None = None,
    ) -> bool:
        """ "Ensures there is a single bundle with the given contents."""
        nbundles = len(e.bundles)
        if nbundles > 1:
            return False

        task_id = _task_id(e)
        if nbundles == 0:
            competition_bundle_id, status = await self.competition_api.submit_bundle(
                task_id, competition_pov_id, competition_patch_id or "", competition_sarif_id or ""
            )
            if competition_bundle_id:
                e.bundles.append(
                    Bundle(
                        bundle_id=competition_bundle_id,
                        task_id=task_id,
                        competition_pov_id=competition_pov_id,
                        competition_patch_id=competition_patch_id,
                        competition_sarif_id=competition_sarif_id,
                    )
                )
                log_entry(
                    e,
                    i=i,
                    msg=f"Submitted bundle {competition_bundle_id} for patch {competition_patch_id} and sarif {competition_sarif_id}",
                )
                return True
            else:
                log_entry(
                    e,
                    i=i,
                    msg=f"Failed to submit bundle, status: {status}. Will keep trying.",
                )
                return False
        else:
            bundle = e.bundles[0]
            bundle_needs_update = (competition_patch_id and bundle.competition_patch_id != competition_patch_id) or (
                competition_sarif_id and bundle.competition_sarif_id != competition_sarif_id
            )

            if not bundle_needs_update:
                return False

            if competition_patch_id:
                bundle.competition_patch_id = competition_patch_id
            if competition_sarif_id:
                bundle.competition_sarif_id = competition_sarif_id

            log_entry(e, i=i, msg="Patching bundle")
            success, status = await self.competition_api.patch_bundle(
                bundle.task_id,
                bundle.bundle_id,
                bundle.competition_pov_id,
                bundle.competition_patch_id,
                bundle.competition_sarif_id,
            )
            if success:
                log_entry(
                    e,
                    i=i,
                    msg=f"Patched bundle {bundle.bundle_id} with patch {competition_patch_id} and sarif {competition_sarif_id}",
                )
                return True

            log_entry(e, i=i, msg=f"Failed to patch bundle {bundle.bundle_id}. Status: {status}. Will keep trying.")
            return False

    async def _ensure_patch_is_bundled(self, i: int, e: SubmissionEntry) -> bool:
        """
        Create or update bundle to include current passed patch with successful POV.
        """
        current_patch = _current_patch(e)
        if not current_patch or current_patch.result != SubmissionResult.PASSED:
            return False

        if len(e.bundles) > 1:
            return False

        competition_pov_id = e.bundles[0].competition_pov_id if e.bundles else _get_first_successful_pov_id(e)
        if not competition_pov_id:
            logger.error(f"No competition PoV ID found for submission {e.submission_id}")
            return False

        return await self._ensure_bundle_contents(
            i, e, competition_pov_id, competition_patch_id=current_patch.competition_patch_id
        )

    async def _get_available_sarifs_for_matching(self, task_id: str) -> List[SARIFBroadcastDetail]:
        """Get SARIFs that are available for matching for the given task."""
        sarifs = await self.sarif_store.get_by_task_id(task_id)
        if not sarifs:
            return []

        already_submitted_sarifs = {
            bundle.competition_sarif_id
            async for _, submission_entry in self._enumerate_task_submissions(task_id)
            for bundle in submission_entry.bundles
            if bundle.competition_sarif_id
        }
        return [sarif for sarif in sarifs if sarif.sarif_id not in already_submitted_sarifs]

    async def _ensure_sarif_is_bundled(self, i: int, e: SubmissionEntry) -> bool:
        """
        Find external SARIF reports that match this entry's POVs and bundle them.
        """
        if e.bundles and e.bundles[0].competition_sarif_id:
            return False

        competition_pov_id = _get_first_successful_pov_id(e)
        if not competition_pov_id:
            return False

        for sarif in await self._get_available_sarifs_for_matching(_task_id(e)):
            for crash in e.crashes:
                match_result = match(sarif, crash.crash)
                if match_result and match_result.matches_lines:
                    log_entry(
                        e,
                        i=i,
                        msg=f"Found matching SARIF: {sarif.sarif_id}: {match_result}. Will bundle it.",
                        fn=logging.info,
                    )
                    return await self._ensure_bundle_contents(
                        i, e, competition_pov_id, competition_sarif_id=sarif.sarif_id
                    )
        return False

    async def _confirm_matched_sarifs(self, i: int, e: SubmissionEntry) -> bool:
        """Ensure the SARIF is submitted to the competition API"""
        if len(e.bundles) != 1:
            return False

        bundle = e.bundles[0]
        if not bundle.competition_sarif_id or bundle.competition_sarif_id in self.matched_sarifs:
            return False

        success, status = await self.competition_api.submit_matching_sarif(_task_id(e), bundle.competition_sarif_id)
        if success:
            await self._insert_matched_sarif(bundle.competition_sarif_id)
            return True
        else:
            log_entry(
                e,
                i=i,
                msg=f"Failed to confirm SARIF {bundle.competition_sarif_id}. Status: {status}. Will keep trying.",
            )
            return False

    def _reorder_patches_by_completion(self, e: SubmissionEntry) -> None:
        """
        Reorder patches starting from patch_idx so that completed ones come first.
        """
        if not _current_patch(e):
            return

        all_patches = list(e.patches)
        processed_patches = all_patches[: e.patch_idx]
        pending_patches = all_patches[e.patch_idx :]
        patches_with_content = [p for p in pending_patches if p.patch]
        patches_without_content = [p for p in pending_patches if not p.patch]
        reordered_patches = processed_patches + patches_with_content + patches_without_content
        del e.patches[:]
        e.patches.extend(reordered_patches)

    async def record_patch(self, patch: Patch) -> bool:
        """
        Entry point for completed patches from patch generators.
        """
        key = patch.internal_patch_id
        maybe_patch = await self._find_patch(key)
        if not maybe_patch:
            logger.error(f"Patch {key} not found in any submission (task expired/cancelled?). Will discard.")
            return True

        i, e, entry_patch = maybe_patch
        if entry_patch.patch:
            new_patch_tracker = self._new_patch_tracker()
            new_patch_tracker.patch = patch.patch
            e.patches.append(new_patch_tracker)
        else:
            entry_patch.patch = patch.patch

        self._reorder_patches_by_completion(e)
        await self._persist()
        log_entry(e, i=i, msg="Patch added")
        return True

    async def _pov_reproduce_patch_status(
        self, patch: SubmissionEntryPatch, crashes: List[CrashWithId], task_id: str
    ) -> List[POVReproduceResponse | None]:
        result = []
        for crash_with_id in crashes:
            if crash_with_id.result in [
                SubmissionResult.FAILED,
                SubmissionResult.DEADLINE_EXCEEDED,
                SubmissionResult.INCONCLUSIVE,
            ]:
                continue

            request = POVReproduceRequest(
                task_id=task_id,
                internal_patch_id=patch.internal_patch_id,
                harness_name=crash_with_id.crash.crash.harness_name,
                sanitizer=crash_with_id.crash.crash.target.sanitizer,
                pov_path=crash_with_id.crash.crash.crash_input_path,
            )
            status = await self.pov_reproduce_status.request_status(request)
            result.append(status)
        return result

    async def _pov_reproduce_status_request(
        self, e: SubmissionEntry, patch_idx: int
    ) -> List[POVReproduceResponse | None]:
        patch = e.patches[patch_idx]
        task_id = _task_id(e)
        return await self._pov_reproduce_patch_status(patch, e.crashes, task_id)

    async def _check_all_povs_are_mitigated(self, i: int, e: SubmissionEntry, patch_idx: int) -> bool | None:
        """
        Test if patch at patch_idx mitigates all POVs.
        """
        statuses = await self._pov_reproduce_status_request(e, patch_idx)
        n_pending = sum(1 for status in statuses if status is None)
        n_mitigated = sum(1 for status in statuses if status is not None and not status.did_crash)
        n_failed = sum(1 for status in statuses if status is not None and status.did_crash)
        log_entry(
            e,
            i=i,
            msg=f"Remediation status: Pending: {n_pending}, Mitigated: {n_mitigated}, Failed: {n_failed}",
            fn=logger.debug,
        )

        if any(status is not None and status.did_crash for status in statuses):
            return False
        if any(status is None for status in statuses):
            return None
        return True

    @staticmethod
    def _new_patch_tracker() -> SubmissionEntryPatch:
        """Create a new patch tracker."""
        return SubmissionEntryPatch(internal_patch_id=str(uuid.uuid4()))

    async def _enqueue_patch_requests(
        self, confirmed_vulnerability: ConfirmedVulnerability, q: NatsQueue[ConfirmedVulnerability] | None
    ) -> None:
        """Push N copies of vulnerability to queue for parallel patch generation."""
        if q is None:
            q = NatsQueueFactory(self.jetstream.client, self.jetstream).create(QueueNames.CONFIRMED_VULNERABILITIES)
            await q.__post_init__()

        for _ in range(self.patch_requests_per_vulnerability):
            await q.push(confirmed_vulnerability)

    async def _should_wait_for_patch_mitigation_merge(self, i: int, e: SubmissionEntry) -> bool:
        """
        Check if this submission's POVs are mitigated by patches from other submissions.
        """
        async for j, e2 in self._enumerate_task_submissions(_task_id(e)):
            if i == j:
                continue

            maybe_patch = _current_patch(e2)
            if not maybe_patch or not maybe_patch.competition_patch_id:
                continue

            patch_mitigates_povs = await self._pov_reproduce_patch_status(maybe_patch, e.crashes, _task_id(e))
            if any(status is None for status in patch_mitigates_povs):
                log_entry(e, i=i, msg="Waiting for patch mitigation evaluation")
                return True
            if any(status is not None and not status.did_crash for status in patch_mitigates_povs):
                log_entry(
                    e,
                    i=i,
                    msg=f"Patch competition_patch_id={maybe_patch.competition_patch_id} mitigates at least one PoV, wait for merge",
                )
                return True
        return False

    async def _merge_entries_by_patch_mitigation(self) -> None:
        """
        Cross-submission optimization: merge entries when one submission's patch fixes another's POVs.
        """
        async for i, e in self._enumerate_submissions():
            try:
                task_id = _task_id(e)
                current_patch = _current_patch(e)
                if (
                    not current_patch
                    or not current_patch.patch
                    or not current_patch.build_outputs
                    or not all(b.task_dir for b in current_patch.build_outputs)
                ):
                    continue

                to_merge = [(i, e)]
                async for j, e2 in self._enumerate_task_submissions(task_id):
                    if i == j:
                        continue
                    pov_reproduce_statuses = await self._pov_reproduce_patch_status(current_patch, e2.crashes, task_id)
                    if any(status is not None and not status.did_crash for status in pov_reproduce_statuses):
                        to_merge.append((j, e2))

                if len(to_merge) > 1:
                    merged_indices = [j for j, _ in to_merge[1:]]
                    logger.info(
                        f"[{i}:{_task_id(e)}] Merging {len(to_merge) - 1} similar submissions into this one. Merging indices: {', '.join(map(str, merged_indices))}"
                    )
                    await self._consolidate_similar_submissions(crash=None, similar_entries=to_merge)
            except Exception as err:
                logger.error(f"[{i}:{_task_id(e)}] Error merging entries by patch mitigation: {err}")

    async def process_cycle(self) -> None:
        """
        Main processing loop that advances all submission state machines.
        """
        async for i, e in self._enumerate_submissions():
            try:
                needs_persist = False
                if await self._confirm_matched_sarifs(i, e):
                    needs_persist = True
                if await self._ensure_sarif_is_bundled(i, e):
                    needs_persist = True
                if await self._ensure_patch_is_bundled(i, e):
                    needs_persist = True
                if await self._update_patch_status(i, e):
                    needs_persist = True
                if await self._request_patch_if_needed(i, e):
                    needs_persist = True
                if await self._request_patched_builds_if_needed(i, e):
                    needs_persist = True
                if await self._submit_patch_if_good(i, e):
                    needs_persist = True
                if await self._update_pov_status(i, e):
                    needs_persist = True
                if await self._submit_pov_if_needed(i, e):
                    needs_persist = True
                if await self._ensure_single_bundle(i, e):
                    needs_persist = True

                if needs_persist:
                    await self._persist()

            except Exception:
                logger.exception(f"[{i}:{_task_id(e)}] Error processing submission")

        try:
            await self._merge_entries_by_patch_mitigation()
        except Exception as err:
            logger.error(f"Error merging entries by patch mitigation: {err}")
