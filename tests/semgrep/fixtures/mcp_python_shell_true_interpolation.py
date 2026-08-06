import subprocess
import os

container_id = "x"

# ruleid: mcp-python-shell-true-interpolation
subprocess.run(f"docker exec {container_id} ls", shell=True)

# ruleid: mcp-python-shell-true-interpolation
subprocess.Popen(f"docker exec {container_id} ls", shell=True)

# ruleid: mcp-python-shell-true-interpolation
subprocess.call(f"docker exec {container_id} ls", shell=True)

# ruleid: mcp-python-shell-true-interpolation
os.system(f"ls {container_id}")

# ruleid: mcp-python-shell-true-interpolation
subprocess.run("docker exec {} ls".format(container_id), shell=True)

# ok: mcp-python-shell-true-interpolation
subprocess.run("docker ps -a", shell=True)

# ok: mcp-python-shell-true-interpolation
subprocess.run(["docker", "exec", container_id, "ls"], shell=False)
