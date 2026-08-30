"""
SSH Process Isolation & Containment Executor
Connects to monitored Linux hosts via paramiko to execute SIGSTOP process isolation and verify process states.
"""

import io
import logging
import os
import re
from typing import Any, Dict, Optional, Tuple
try:
    import paramiko
except ImportError:
    paramiko = None

from .telegram_notifier import get_telegram_notifier


logger = logging.getLogger("brahma.dharma.ssh")


class SSHProcessIsolator:
    """
    Executes real process containment (kill -SIGSTOP) and verification over SSH using paramiko.
    """

    def __init__(self, default_user: str = "root", default_port: int = 22):
        self.default_user = default_user
        self.default_port = default_port
        self.telegram = get_telegram_notifier()

    def _get_ssh_credentials(
        self,
        hostname: str,
        supabase_client=None,
    ) -> Dict[str, Any]:
        """Lookup host SSH credentials from Supabase agent_registry or environment variables."""
        sanitized = re.sub(r"[^a-zA-Z0-9_]", "_", hostname).upper()
        
        # Default env fallbacks
        host = os.environ.get(f"SSH_HOST_{sanitized}", hostname)
        port = int(os.environ.get(f"SSH_PORT_{sanitized}", str(self.default_port)))
        user = os.environ.get(f"SSH_USER_{sanitized}", self.default_user)
        key_str = os.environ.get(f"SSH_KEY_{sanitized}") or os.environ.get("SSH_PRIVATE_KEY")
        password = os.environ.get(f"SSH_PASSWORD_{sanitized}") or os.environ.get("SSH_DEFAULT_PASSWORD")

        if supabase_client:
            try:
                res = (
                    supabase_client.table("agent_registry")
                    .select("ssh_host, ssh_port, ssh_user, ssh_key")
                    .eq("hostname", hostname)
                    .execute()
                )
                if res.data and len(res.data) > 0:
                    row = res.data[0]
                    host = row.get("ssh_host") or host
                    port = int(row.get("ssh_port") or port)
                    user = row.get("ssh_user") or user
                    key_str = row.get("ssh_key") or key_str
            except Exception as e:
                logger.debug(f"Failed querying agent_registry for SSH config of {hostname}: {e}")

        return {
            "host": host,
            "port": port,
            "user": user,
            "key_str": key_str,
            "password": password,
        }

    def _create_ssh_client(self, creds: Dict[str, Any]):
        """Instantiate configured paramiko SSHClient."""
        if paramiko is None:
            raise RuntimeError("paramiko library is not installed")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())


        connect_kwargs: Dict[str, Any] = {
            "hostname": creds["host"],
            "port": creds["port"],
            "username": creds["user"],
            "timeout": 8.0,
        }

        if creds.get("key_str"):
            try:
                key_file = io.StringIO(creds["key_str"].strip())
                # Try RSA first, then Ed25519 / generic
                try:
                    pkey = paramiko.RSAKey.from_private_key(key_file)
                except Exception:
                    key_file.seek(0)
                    pkey = paramiko.Ed25519Key.from_private_key(key_file)
                connect_kwargs["pkey"] = pkey
            except Exception as e:
                logger.warning(f"Error parsing SSH private key: {e}")

        if creds.get("password") and "pkey" not in connect_kwargs:
            connect_kwargs["password"] = creds["password"]

        client.connect(**connect_kwargs)
        return client

    async def isolate_process(
        self,
        hostname: str,
        pid: int,
        action_id: str,
        supabase_client=None,
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Execute SIGSTOP on target PID and verify stopped status ('T').
        Returns (status: 'EXECUTED' | 'STALE_PID' | 'FAILED', execution_detail: dict)
        """
        creds = self._get_ssh_credentials(hostname, supabase_client)
        ssh_client = None

        try:
            ssh_client = self._create_ssh_client(creds)
            
            # Step 1: Check if PID is alive
            check_cmd = f"ps -p {pid} -o stat="
            _, stdout, stderr = ssh_client.exec_command(check_cmd, timeout=5.0)
            initial_stat = stdout.read().decode("utf-8").strip()
            check_err = stderr.read().decode("utf-8").strip()

            if not initial_stat:
                logger.warning(f"PID {pid} not found on host {hostname}. Marking action STALE_PID.")
                return "STALE_PID", {
                    "initial_check": "PID not found",
                    "stderr": check_err,
                }

            # Step 2: Dispatch kill -SIGSTOP {pid}
            sigstop_cmd = f"kill -SIGSTOP {pid}"
            _, stdout, stderr = ssh_client.exec_command(sigstop_cmd, timeout=5.0)
            sig_out = stdout.read().decode("utf-8").strip()
            sig_err = stderr.read().decode("utf-8").strip()

            # Step 3: Verify execution: process status must contain 'T' (stopped)
            _, stdout, stderr = ssh_client.exec_command(check_cmd, timeout=5.0)
            verified_stat = stdout.read().decode("utf-8").strip()

            execution_detail = {
                "initial_stat": initial_stat,
                "sigstop_output": sig_out,
                "sigstop_error": sig_err,
                "verified_stat": verified_stat,
                "command": sigstop_cmd,
            }

            if "T" in verified_stat:
                logger.info(f"Successfully isolated PID {pid} on {hostname} via SIGSTOP (stat: {verified_stat}).")
                return "EXECUTED", execution_detail
            elif not verified_stat:
                logger.warning(f"PID {pid} terminated before SIGSTOP on {hostname}.")
                return "STALE_PID", execution_detail
            else:
                logger.warning(f"Process {pid} on {hostname} not stopped after SIGSTOP (stat: {verified_stat}).")
                return "FAILED", execution_detail

        except Exception as e:
            logger.error(f"SSH connection / command execution failed for {hostname}: {e}")
            await self.telegram.notify_execution_failed(
                action_id=action_id,
                action_type="PROCESS_ISOLATION",
                hostname=hostname,
                target=f"PID {pid}",
                error_detail=str(e),
            )
            return "FAILED", {"error": str(e)}

        finally:
            if ssh_client:
                try:
                    ssh_client.close()
                except Exception:
                    pass

    async def resume_process(
        self,
        hostname: str,
        pid: int,
        action_id: str,
        supabase_client=None,
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Execute SIGCONT to reverse process isolation (e.g. on false positive rejection).
        """
        creds = self._get_ssh_credentials(hostname, supabase_client)
        ssh_client = None

        try:
            ssh_client = self._create_ssh_client(creds)
            sigcont_cmd = f"kill -SIGCONT {pid}"
            _, stdout, stderr = ssh_client.exec_command(sigcont_cmd, timeout=5.0)
            sig_out = stdout.read().decode("utf-8").strip()

            check_cmd = f"ps -p {pid} -o stat="
            _, stdout, stderr = ssh_client.exec_command(check_cmd, timeout=5.0)
            verified_stat = stdout.read().decode("utf-8").strip()

            detail = {
                "command": sigcont_cmd,
                "sigcont_output": sig_out,
                "verified_stat": verified_stat,
            }

            if "T" not in verified_stat:
                logger.info(f"Successfully resumed PID {pid} on {hostname} via SIGCONT.")
                return "REVERSED", detail
            else:
                return "FAILED", detail

        except Exception as e:
            logger.error(f"Failed reversing SIGCONT on {hostname}: {e}")
            return "FAILED", {"error": str(e)}

        finally:
            if ssh_client:
                try:
                    ssh_client.close()
                except Exception:
                    pass


_ssh_isolator = SSHProcessIsolator()


def get_ssh_process_isolator() -> SSHProcessIsolator:
    return _ssh_isolator
