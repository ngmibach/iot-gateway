import streamlit as st

from ..utils import (
    gitea_dispatch_workflow,
    GITEA_URL,
    GITEA_OWNER,
    GITEA_REPO,
)

# ═══════════════════════════════════════════════════════════════════
#  CONTROL PLANE — Trigger Gitea Actions workflows
# ═══════════════════════════════════════════════════════════════════
def render_control_plane():
    st.markdown('<h1 style="color:#a6e3a1;">Control Plane</h1>', unsafe_allow_html=True)


    st.markdown("---")

    # Action selector
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
    )

    st.markdown("")

    # Forms / inputs per action
    if action == "Add / Register new MQTT User":
        st.subheader("Add / Register new MQTT User")

        with st.form("form_add_user", clear_on_submit=False):
            c1, c2 = st.columns(2)
            with c1:
                user_id = st.text_input("USER_ID *", value="", placeholder="sensor4", help="MQTT username (also used for ACL)")
                user_pass = st.text_input("USER_PASSWORD *", value="", type="password", help="Password for MQTT port 1883")
            with c2:
                user_ip = st.text_input("USER_IP *", value="", placeholder="192.168.1.50", help="IP address to allow through HAProxy")
                topic_read = st.text_input("USER_TOPIC_READ (optional)", value="", placeholder="sensors/+/data")
                topic_rw = st.text_input("USER_TOPIC_READ_WRITE (optional)", value="", placeholder="sensors/+/command")

            submitted = st.form_submit_button("🚀 Trigger Add New User", type="primary", use_container_width=True)

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
            username = st.text_input(
                "USERNAME *",
                value="sensor3",
                placeholder="sensor3",
                help="MQTT username whose ACL will be updated"
            )

            col1, col2 = st.columns(2)
            with col1:
                readwrite_topics = st.text_input(
                    "ReadWrite Topics (comma-separated)",
                    value="",
                    placeholder="sensors/sensor3/#,home/#",
                    help="New readwrite topics. Leave empty to keep existing."
                )
                delete_readwrite = st.text_input(
                    "Delete ReadWrite Rules",
                    value="",
                    placeholder="sensors/sensor3/#",
                    help="ReadWrite rules to remove (comma-separated)"
                )

            with col2:
                read_topics = st.text_input(
                    "Read-only Topics (comma-separated)",
                    value="",
                    placeholder="sensors/+/status,public/#",
                    help="New read-only topics. Leave empty to keep existing."
                )
                delete_read = st.text_input(
                    "Delete Read Rules",
                    value="",
                    placeholder="",
                    help="Read rules to remove (comma-separated)"
                )

            submitted = st.form_submit_button(
                "🚀 Update ACL Rules", 
                type="primary", 
                use_container_width=True
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
                        result = gitea_dispatch_workflow(
                            "update_acl.yaml",   # ← Make sure this matches your workflow filename
                            inputs=inputs
                        )
                    _show_dispatch_result(result, "update_acl.yaml")

    elif action == "Update Device IP(s) in HAProxy allow-list":
        st.subheader("Update Device IP(s) in HAProxy allow-list")

        with st.form("form_update_ip", clear_on_submit=False):
            allowed = st.text_input(
                "ALLOWED_DEVICE_IP (comma separated)",
                value="",
                placeholder="192.168.10.45, 10.0.0.12",
                help="IPs to add to the allow list",
            )
            denied = st.text_input(
                "DENIED_DEVICE_IP (comma separated)",
                value="",
                placeholder="192.168.10.99",
                help="IPs to remove from the allow list",
            )
            remove_all = st.selectbox(
                "REMOVE_ALL_IP",
                options=["no", "yes"],
                index=0,
                help="If 'yes', the entire allowed-ips.txt will be cleared first.",
            )

            submitted = st.form_submit_button("🚀 Trigger Update Device IPs", type="primary", use_container_width=True)

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

        if st.button("🔐 Trigger Certificate Rotation (update_key)", type="primary", use_container_width=True):
            with st.spinner("Dispatching update_key.yaml (certificate rotation)..."):
                result = gitea_dispatch_workflow("update_key.yaml", inputs=None)
            _show_dispatch_result(result, "update_key.yaml")

    elif action == "Clear / Delete Logs (Mosquitto, Node-RED, Suricata)":
        st.subheader("Clear / Delete Logs")

        if st.button("🗑️ Trigger Log Cleanup (delete logs)", type="primary", use_container_width=True):
            with st.spinner("Dispatching cron_job_delete_log.yaml..."):
                result = gitea_dispatch_workflow("cron_job_delete_log.yaml", inputs=None)
            _show_dispatch_result(result, "cron_job_delete_log.yaml")

    st.markdown("---")
    st.caption(
        f"Gitea: **{GITEA_URL}** &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"Repository: **{GITEA_OWNER}/{GITEA_REPO}** &nbsp;&nbsp;|&nbsp;&nbsp; "
        "Actions can be monitored live in the Gitea web UI under the repository → Actions tab."
    )

    # Quick links
    col1, col2 = st.columns(2)
    with col1:
        st.link_button(
            "Open Gitea Repository",
            f"{GITEA_URL}/{GITEA_OWNER}/{GITEA_REPO}",
            use_container_width=True,
        )
    with col2:
        st.link_button(
            "View Recent Action Runs",
            f"{GITEA_URL}/{GITEA_OWNER}/{GITEA_REPO}/actions",
            use_container_width=True,
        )


def _show_dispatch_result(result: dict, workflow_file: str):
    """Helper to render consistent success / error feedback after a dispatch."""
    if result.get("success"):
        st.success(f"Workflow **{workflow_file}** dispatched successfully! (HTTP {result.get('status_code')})")
        st.info(
            "The Gitea runner should pick it up shortly. Check the **Actions** tab in Gitea for live logs and status.",
            icon="ℹ️",
        )
        run_url = f"{GITEA_URL}/{GITEA_OWNER}/{GITEA_REPO}/actions"
        st.markdown(f"[→ View runs in Gitea]({run_url})")
    else:
        st.error(f"Failed to dispatch **{workflow_file}**")
        if "status_code" in result:
            st.code(f"HTTP {result['status_code']}")
        if "error" in result:
            st.code(result["error"])
        st.caption("Common issues: wrong credentials, repo not seeded, runner not registered, or network reachability from Streamlit container to Gitea.")
