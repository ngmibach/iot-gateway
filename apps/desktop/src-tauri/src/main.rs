#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    iot_gateway_monitor_lib::run();
}
