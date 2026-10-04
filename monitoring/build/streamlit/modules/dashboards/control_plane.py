import os
import streamlit as st

from ..utils import (
    CONTROL_SERVICE_URL,
    GATEWAY_ID,
    GITEA_OWNER,
    GITEA_REPO,
    GITEA_URL,
    USE_LEGACY_GITEA,
    control_cert_bundle_url,
    control_delete_device,
    control_list_devices,
    control_list_gateways,
    control_register_device,
    gitea_dispatch_workflow,
)


auto_refresh = True
refresh_seconds = 15


def _gateway_choices() -> tuple[list[str], dict[str, dict]]:
    result = control_list_gateways()
    by_id: dict[str, dict] = {}
    if result.get("success"):
        for gw in result.get("gateways") or []:
            gid = gw.get("id")
            if gid:
                by_id[str(gid)] = gw
    ids = list(by_id.keys())
    env_gid = GATEWAY_ID or os.environ.get("IOTGW_GATEWAY_ID", "").strip()
    if env_gid and env_gid not in by_id:
        ids = [env_gid] + ids
        by_id.setdefault(env_gid, {"id": env_gid, "host": "(env)"})
    return ids, by_id


# ═══════════════════════════════════════════════════════════════════
#  CONTROL PLANE — FastAPI SSH actions (legacy Gitea optional)
# ═══════════════════════════════════════════════════════════════════
def render_control_plane():
    st.markdown('<h1 style="color:#a6e3a1;">Control Plane</h1>', unsafe_allow_html=True)

    if USE_LEGACY_GITEA:
        st.warning("Legacy Gitea Actions mode is enabled (`USE_LEGACY_GITEA=1`).", icon="⚠️")
        _render_legacy_gitea()
        return

    st.caption(
        f"Control service: **{CONTROL_SERVICE_URL}** — Register Device runs via "
        "SSH playbooks (whitelist + ACL + mTLS cert + local registry)."
    )
    st.markdown("---")

    action = st.selectbox(
        "Select Action",
        options=[
            "Add / Register new MQTT User",
            "List registered devices",
            "Unregister device",
            "Update Access Control (ACL) for MQTT User (legacy Gitea)",
            "Update Device IP(s) in HAProxy allow-list (legacy Gitea)",
            "Rotate Server & Client Certificates (Keys) (legacy Gitea)",
            "Clear / Delete Logs (legacy Gitea)",
        ],
        index=0,
        help="Phase-0: Register / list / unregister use FastAPI. Other actions still need playbook wiring.",
    )

    st.markdown("")
    gateway_ids, gateway_meta = _gateway_choices()

    if action == "Add / Register new MQTT User":
        _render_register(gateway_ids, gateway_meta)
    elif action == "List registered devices":
        _render_list_devices(gateway_ids)
    elif action == "Unregister device":
        _render_unregister(gateway_ids)
    else:
        st.info(
            "This action is not yet wired to FastAPI SSH playbooks. "
            "Set `USE_LEGACY_GITEA=1` to dispatch the old Gitea workflow, "
            "or wait for the Actions polish PR.",
            icon="ℹ️",
        )


def _render_register(gateway_ids: list[str], gateway_meta: dict[str, dict]):
    st.subheader("Add / Register new MQTT User")
    if not gateway_ids:
        st.error(
            "No gateway in the control-service registry. "
            "Provision/connect a gateway first, or set `IOTGW_GATEWAY_ID`."
        )
        return

    default_idx = 0
    env_gid = GATEWAY_ID or os.environ.get("IOTGW_GATEWAY_ID", "").strip()
    if env_gid and env_gid in gateway_ids:
        default_idx = gateway_ids.index(env_gid)

    with st.form("form_add_user_api", clear_on_submit=False):
        gid = st.selectbox(
            "Gateway *",
            options=gateway_ids,
            index=default_idx,
            format_func=lambda i: f"{i} ({gateway_meta.get(i, {}).get('host', '?')})",
        )
        c1, c2 = st.columns(2)
        with c1:
            user_id = st.text_input(
                "USER_ID *",
                value="",
                placeholder="sensor4",
                help="MQTT username / cert CN",
            )
            user_pass = st.text_input(
                "USER_PASSWORD *",
                value="",
                type="password",
                help="Min 8 chars; hashed on the operator, never on gateway argv",
            )
            ca_pass = st.text_input(
                "CA passphrase",
                value=os.environ.get("IOTGW_CA_PASSPHRASE", ""),
                type="password",
                help="Gateway CA unlock (or set IOTGW_CA_PASSPHRASE on the control service)",
            )
        with c2:
            user_ip = st.text_input(
                "USER_IP *",
                value="",
                placeholder="192.168.1.50",
                help="IP/CIDR allowed through HAProxy",
            )
            topic_read = st.text_input(
                "USER_TOPIC_READ (optional)",
                value="",
                placeholder="sensors/+/data",
            )
            topic_rw = st.text_input(
                "USER_TOPIC_READ_WRITE (optional)",
                value="",
                placeholder="sensors/+/command",
            )

        submitted = st.form_submit_button(
            "🚀 Register Device",
            type="primary",
            use_container_width=True,
        )

        if submitted:
            if not user_id or not user_pass or not user_ip:
                st.error("USER_ID, USER_PASSWORD and USER_IP are required.")
            elif len(user_pass) < 8:
                st.error("USER_PASSWORD must be at least 8 characters.")
            else:
                with st.spinner("Registering via control service (SSH + cert)..."):
                    result = control_register_device(
                        gid,
                        user_id=user_id.strip(),
                        password=user_pass,
                        ip=user_ip.strip(),
                        topic_read=topic_read.strip() or None,
                        topic_readwrite=topic_rw.strip() or None,
                        ca_passphrase=ca_pass.strip() or None,
                    )
                _show_register_result(result, gid, user_id.strip())


def _show_register_result(result: dict, gateway_id: str, device_id: str):
    if result.get("success"):
        st.success(
            f"Device **{device_id}** registered "
            f"(status={result.get('status', 'ok')}"
            f"{', idempotent' if result.get('idempotent') else ''})."
        )
        device = result.get("device") or {}
        if device.get("cert_fingerprint"):
            st.caption(f"Cert fingerprint: `{device.get('cert_fingerprint')}`")
        token = result.get("cert_bundle_token")
        if token:
            url = control_cert_bundle_url(gateway_id, device_id, token)
            st.info(
                "Client cert bundle is ready for **one-time** download "
                "(≤5 minutes). Save `ca.crt` / `client.crt` / `client.key` locally.",
                icon="🔐",
            )
            st.code(url, language=None)
            st.link_button("Download cert bundle", url, use_container_width=True)
        msg = result.get("message")
        if msg:
            st.caption(msg)
    else:
        st.error("Register Device failed")
        if "status_code" in result:
            st.code(f"HTTP {result['status_code']}")
        if "error" in result:
            st.code(result["error"])
        st.caption(
            "Check control service on 127.0.0.1:9137, gateway SSH credentials, "
            "and CA passphrase."
        )


def _render_list_devices(gateway_ids: list[str]):
    st.subheader("Registered devices")
    if not gateway_ids:
        st.warning("No gateway id available.")
        return
    gid = st.selectbox("Gateway", options=gateway_ids, key="list_devices_gw")
    if st.button("Refresh", type="primary"):
        st.session_state["_devices_refresh"] = True
    result = control_list_devices(gid)
    if not result.get("success"):
        st.error(result.get("error") or "Failed to list devices")
        return
    devices = result.get("devices") or []
    if not devices:
        st.info("No devices registered for this gateway yet.")
        return
    st.dataframe(devices, use_container_width=True)


def _render_unregister(gateway_ids: list[str]):
    st.subheader("Unregister device")
    if not gateway_ids:
        st.warning("No gateway id available.")
        return
    with st.form("form_unregister"):
        gid = st.selectbox("Gateway *", options=gateway_ids)
        device_id = st.text_input("Device ID (MQTT user) *", value="")
        remove_ip = st.checkbox("Also remove device IP from HAProxy allow-list", value=False)
        submitted = st.form_submit_button("🗑️ Unregister", type="primary", use_container_width=True)
        if submitted:
            if not device_id.strip():
                st.error("Device ID is required.")
            else:
                with st.spinner("Unregistering via control service..."):
                    result = control_delete_device(
                        gid,
                        device_id.strip(),
                        remove_ip=remove_ip,
                    )
                if result.get("success"):
                    st.success(result.get("message") or "Device unregistered.")
                else:
                    st.error(result.get("error") or "Unregister failed")


def _render_legacy_gitea():
    """Previous Gitea Actions UI — only when USE_LEGACY_GITEA is set."""
    st.markdown("---")
    action = st.selectbox(
        "Select Action",
        options=[
            "Add / Register new MQTT User",
            "Update Access Control (ACL) for MQTT User",
            "Update Device IP(s) in HAProxy allow-list",
            "Rotate Server & Client Certificates (Keys)",
            "Clear / Delete Logs (Mosquitto, Node-RED, Suricata)",
        ],
        index=0,
        help="Choose the Gitea Action workflow you want to run.",
        key="legacy_action",
    )

    st.markdown("")

    if action == "Add / Register new MQTT User":
        st.subheader("Add / Register new MQTT User")
        with st.form("form_add_user", clear_on_submit=False):
            c1, c2 = st.columns(2)
            with c1:
                user_id = st.text_input("USER_ID *", value="", placeholder="sensor4")
                user_pass = st.text_input("USER_PASSWORD *", value="", type="password")
            with c2:
                user_ip = st.text_input("USER_IP *", value="", placeholder="192.168.1.50")
                topic_read = st.text_input("USER_TOPIC_READ (optional)", value="")
                topic_rw = st.text_input("USER_TOPIC_READ_WRITE (optional)", value="")
            submitted = st.form_submit_button(
                "🚀 Trigger Add New User", type="primary", use_container_width=True
            )
            if submitted:
                if not user_id or not user_pass or not user_ip:
                    st.error("USER_ID, USER_PASSWORD and USER_IP are required.")
                else:
                    inputs = {
                        "USER_ID": user_id.strip(),
                        "USER_PASSWORD": user_pass,
                        "USER_IP": user_ip.strip(),
                        "USER_TOPIC_READ": topic_read.strip(),
                        "USER_TOPIC_READ_WRITE": topic_rw.strip(),
                    }
                    with st.spinner("Dispatching add_new_user workflow..."):
                        result = gitea_dispatch_workflow("add_new_user.yaml", inputs=inputs)
                    _show_dispatch_result(result, "add_new_user.yaml")

    elif action == "Update Access Control (ACL) for MQTT User":
        st.subheader("Update Access Control (ACL) for MQTT User")
        with st.form("form_update_acl", clear_on_submit=False):
            username = st.text_input("USERNAME *", value="sensor3")
            col1, col2 = st.columns(2)
            with col1:
                readwrite_topics = st.text_input("ReadWrite Topics (comma-separated)", value="")
                delete_readwrite = st.text_input("Delete ReadWrite Rules", value="")
            with col2:
                read_topics = st.text_input("Read-only Topics (comma-separated)", value="")
                delete_read = st.text_input("Delete Read Rules", value="")
            submitted = st.form_submit_button(
                "🚀 Update ACL Rules", type="primary", use_container_width=True
            )
            if submitted:
                if not username:
                    st.error("USERNAME is required.")
                else:
                    inputs = {
                        "username": username.strip(),
                        "readwrite_topics": readwrite_topics.strip(),
                        "read_topics": read_topics.strip(),
                        "delete_readwrite": delete_readwrite.strip(),
                        "delete_read": delete_read.strip(),
                    }
                    with st.spinner("Dispatching ACL update workflow..."):
                        result = gitea_dispatch_workflow("update_acl.yaml", inputs=inputs)
                    _show_dispatch_result(result, "update_acl.yaml")

    elif action == "Update Device IP(s) in HAProxy allow-list":
        st.subheader("Update Device IP(s) in HAProxy allow-list")
        with st.form("form_update_ip", clear_on_submit=False):
            allowed = st.text_input("ALLOWED_DEVICE_IP (comma separated)", value="")
            denied = st.text_input("DENIED_DEVICE_IP (comma separated)", value="")
            remove_all = st.selectbox("REMOVE_ALL_IP", options=["no", "yes"], index=0)
            submitted = st.form_submit_button(
                "🚀 Trigger Update Device IPs", type="primary", use_container_width=True
            )
            if submitted:
                inputs = {
                    "ALLOWED_DEVICE_IP": allowed.strip(),
                    "DENIED_DEVICE_IP": denied.strip(),
                    "REMOVE_ALL_IP": remove_all,
                }
                with st.spinner("Dispatching update_device_ip workflow..."):
                    result = gitea_dispatch_workflow("update_device_ip.yaml", inputs=inputs)
                _show_dispatch_result(result, "update_device_ip.yaml")

    elif action == "Rotate Server & Client Certificates (Keys)":
        st.subheader("Rotate Server & Client Certificates (Keys)")
        if st.button(
            "🔐 Trigger Certificate Rotation (update_key)",
            type="primary",
            use_container_width=True,
        ):
            with st.spinner("Dispatching update_key.yaml..."):
                result = gitea_dispatch_workflow("update_key.yaml", inputs=None)
            _show_dispatch_result(result, "update_key.yaml")

    elif action == "Clear / Delete Logs (Mosquitto, Node-RED, Suricata)":
        st.subheader("Clear / Delete Logs")
        if st.button(
            "🗑️ Trigger Log Cleanup (delete logs)",
            type="primary",
            use_container_width=True,
        ):
            with st.spinner("Dispatching cron_job_delete_log.yaml..."):
                result = gitea_dispatch_workflow("cron_job_delete_log.yaml", inputs=None)
            _show_dispatch_result(result, "cron_job_delete_log.yaml")

    st.markdown("---")
    st.caption(
        f"Gitea: **{GITEA_URL}** &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"Repository: **{GITEA_OWNER}/{GITEA_REPO}**"
    )


def _show_dispatch_result(result: dict, workflow_file: str):
    if result.get("success"):
        st.success(
            f"Workflow **{workflow_file}** dispatched successfully! "
            f"(HTTP {result.get('status_code')})"
        )
        run_url = f"{GITEA_URL}/{GITEA_OWNER}/{GITEA_REPO}/actions"
        st.markdown(f"[→ View runs in Gitea]({run_url})")
    else:
        st.error(f"Failed to dispatch **{workflow_file}**")
        if "status_code" in result:
            st.code(f"HTTP {result['status_code']}")
        if "error" in result:
            st.code(result["error"])
