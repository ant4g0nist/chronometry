import os
import subprocess


def runShellCmd(cmd):
    """Run shell command and return output as string."""
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    return out.decode('utf-8')


cmd1 = "go run cmds/cmetry-cli/main.go sign -f examples/sample-report.yaml --passphrase password -b output.json"
cmd2 = "go run cmds/cmetry-cli/main.go record -f output.json -s http://localhost:8008"

for i in range(100):
    with open('examples/sample-report.yaml', 'r') as f:
        report  = f.read()

    oldVersion = report.split("version: ")[1].split("\n")[0]
    newVersion = int(oldVersion) + 1

    report = report.replace("version: " + oldVersion, "version: " + str(newVersion))

    with open('examples/sample-report.yaml', 'w') as f:
        f.write(report)

    runShellCmd(cmd1)
    runShellCmd(cmd2)