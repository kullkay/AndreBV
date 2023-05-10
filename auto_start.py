import os


script_path = input("full path for script.py: ")


service_name = input("name service: ")


unit_file_path = f"/etc/systemd/system/{service_name}.service"


unit_file_content = f"""\
[Unit]
Description=My Script
After=network.target

[Service]
Type=simple
ExecStart = sudo python3 {script_path}


[Install]
WantedBy=multi-user.target
"""


with open(unit_file_path, "w") as f:
    f.write(unit_file_content)


os.system(f"systemctl daemon-reload")
os.system(f"systemctl enable {service_name}")
os.system(f"systemctl start {service_name}")