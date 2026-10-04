"""Lab routes — short-lived fake_sensor compose (optional demos only)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from lab.lifecycle import LabFakeSensorManager

from .deps import AppState, get_state, require_token
from .schemas import LabFakeSensorsStartRequest, LabFakeSensorsStatus

router = APIRouter(dependencies=[Depends(require_token)])


def _manager(state: AppState) -> LabFakeSensorManager:
    mgr = getattr(state, "lab_manager", None)
    if mgr is None:
        mgr = LabFakeSensorManager(state.settings.data_dir / "lab")
        state.lab_manager = mgr  # type: ignore[attr-defined]
    return mgr


def _status_out(st) -> LabFakeSensorsStatus:
    return LabFakeSensorsStatus(
        running=st.running,
        gateway_ip=st.gateway_ip,
        sensors=list(st.sensors),
        duration_minutes=st.duration_minutes,
        started_at=st.started_at,
        stops_at=st.stops_at,
        warning=st.warning,
        compose_ps=st.compose_ps,
        staged_root=st.staged_root,
        detail=st.detail,
    )


@router.post("/lab/fake-sensors/start", response_model=LabFakeSensorsStatus)
def start_fake_sensors(
    body: LabFakeSensorsStartRequest,
    state: AppState = Depends(get_state),
) -> LabFakeSensorsStatus:
    mgr = _manager(state)
    try:
        st = mgr.start(
            gateway_ip=body.gateway_ip,
            duration_minutes=body.duration_minutes,
            sensors=body.sensors,
            build=body.build,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)
        ) from exc
    return _status_out(st)


@router.post("/lab/fake-sensors/stop", response_model=LabFakeSensorsStatus)
def stop_fake_sensors(
    state: AppState = Depends(get_state),
) -> LabFakeSensorsStatus:
    return _status_out(_manager(state).stop())


@router.get("/lab/fake-sensors/status", response_model=LabFakeSensorsStatus)
def fake_sensors_status(
    state: AppState = Depends(get_state),
) -> LabFakeSensorsStatus:
    return _status_out(_manager(state).status())
