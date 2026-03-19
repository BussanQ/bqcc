import subprocess


def bash(command: str) -> str:
    """Run a shell command and return stdout + stderr."""
    try:
        result = subprocess.run(
            command, shell=True,
            capture_output=True, text=True, timeout=60,
        )
        output = result.stdout + result.stderr
        return output if output.strip() else "(no output)"
    except subprocess.TimeoutExpired:
        return "Error: command timed out after 60 seconds"
    except Exception as e:
        return f"Error: {e}"
