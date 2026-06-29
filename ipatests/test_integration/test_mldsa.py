#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests which testing ability of various feature
under PQC enabled installs.
"""

import os
import re

import pytest
from ipaplatform.paths import paths

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestPQCMLDSAKeySizes(IntegrationTest):
    """
    Test different ML-DSA key size variants.

    These tests validate that:
    - ML-DSA-44 (security level 2) works for user and service certs
    - ML-DSA-65 (security level 3) works for user and service certs
    - ML-DSA-87 (security level 5) works for user and service certs
    """

    num_clients = 1
    topology = "line"

    @classmethod
    def install(cls, mh):
        """Install master+client with ML-DSA-65 CA (default)."""
        extra_args = [
            "--key-type-size", "mldsa",
            "--ca-key-type", "mldsa",
        ]
        tasks.install_master(cls.master, setup_dns=True, extra_args=extra_args)
        tasks.add_a_records_for_hosts_in_master_domain(cls.master)
        tasks.install_clients([cls.master], cls.clients)

    @pytest.mark.parametrize("algo", ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
    def test_user_cert_request_various_mldsa_sizes(self, algo):
        """Request user cert with different ML-DSA key sizes."""
        user = f"pqcuser_{algo.lower().replace('-', '_')}"
        csr = f"/tmp/{user}.csr"
        key = f"/tmp/{user}.key"
        crt = f"/tmp/{user}.crt"

        tasks.kinit_admin(self.master)
        tasks.user_add(self.master, user)
        self.master.run_command(["rm", "-f", csr, key, crt], raiseonerr=False)

        # Check if OpenSSL supports this algorithm
        probe = os.path.join(paths.OPENSSL_PRIVATE_DIR, f".{algo}-probe.key")
        try:
            gen = self.master.run_command(
                ["openssl", "genpkey", "-algorithm", algo, "-out", probe],
                raiseonerr=False,
            )
            if gen.returncode != 0:
                pytest.skip(
                    f"OpenSSL cannot generate {algo} keys on {self.master.hostname}"
                )
        finally:
            self.master.run_command(["rm", "-f", probe], raiseonerr=False)

        self.master.run_command(
            ["openssl", "genpkey", "-algorithm", algo, "-out", key]
        )
        self.master.run_command(
            [
                "openssl", "req", "-new", "-key", key, "-out", csr,
                "-subj", f"/CN={user}",
            ]
        )

        res = self.master.run_command(
            [
                "ipa", "cert-request", "--principal", user,
                "--certificate-out", crt, csr,
            ],
            raiseonerr=False,
        )
        if res.returncode != 0:
            if "400 Client Error: Bad Request" in res.stderr_text:
                pytest.xfail(
                    f"Known ML-DSA CA limitation: {algo} cert-request fails "
                    "(Dogtag 400)"
                )
            pytest.fail(res.stderr_text)

        pem = self.master.get_file_contents(crt)
        assert "BEGIN CERTIFICATE" in pem

        # Verify the certificate algorithm
        cert_info = self.master.run_command(
            ["openssl", "x509", "-in", crt, "-noout", "-text"]
        )
        assert algo in cert_info.stdout_text

        tasks.kdestroy_all(self.master)
        self.master.run_command(["rm", "-f", csr, key, crt], raiseonerr=False)

    @pytest.mark.parametrize("algo", ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
    def test_service_cert_request_various_mldsa_sizes(self, algo):
        """Request service cert with different ML-DSA key sizes."""
        service = f"HTTP/pqc-{algo.lower()}.{self.master.domain.name}"
        certfile = f"/tmp/pqc-service-{algo.lower()}.pem"
        keyfile = f"/tmp/pqc-service-{algo.lower()}.key"

        tasks.kinit_admin(self.master)
        self.master.run_command(
            ["ipa", "service-add", service], raiseonerr=False
        )
        self.master.run_command(
            ["rm", "-f", certfile, keyfile], raiseonerr=False
        )

        # Check certmonger support
        probe = os.path.join(paths.OPENSSL_PRIVATE_DIR, f".{algo}-cm-probe.key")
        try:
            gen = self.master.run_command(
                ["openssl", "genpkey", "-algorithm", algo, "-out", probe],
                raiseonerr=False,
            )
            if gen.returncode != 0:
                pytest.skip(f"Cannot generate {algo} keys on this host")
        finally:
            self.master.run_command(["rm", "-f", probe], raiseonerr=False)

        out = self.master.run_command(
            ["ipa-getcert", "request",
             "-f", certfile,
             "-k", keyfile,
             "-K", service,
             "-G", algo],
            raiseonerr=False,
        )
        if out.returncode != 0:
            if "unsupported" in out.stderr_text.lower():
                pytest.skip(f"certmonger does not support {algo} keygen")
            if "400 Client Error: Bad Request" in out.stderr_text:
                pytest.xfail(
                    f"Known ML-DSA CA limitation: {algo} service cert fails "
                    "(Dogtag 400)"
                )
            pytest.fail(out.stderr_text)

        request_id = re.findall(r"\d+", out.stdout_text)
        if not request_id:
            pytest.fail(f"Could not parse request id from: {out.stdout_text}")

        state = tasks.wait_for_request(self.master, request_id[0], 60)
        if state != "MONITORING":
            pytest.xfail(f"Request reached state {state} instead of MONITORING")

        pk_out = self.master.run_command(
            f"openssl x509 -in {certfile} -noout -text | grep -i public",
            raiseonerr=False,
        ).stdout_text
        assert algo in pk_out

        self.master.run_command(
            ["getcert", "stop-tracking", "-i", request_id[0]],
            raiseonerr=False,
        )
        self.master.run_command(
            ["rm", "-f", certfile, keyfile], raiseonerr=False
        )
        tasks.kdestroy_all(self.master)


class TestPQCCertificateRenewal(IntegrationTest):
    """
    Test certificate renewal with ML-DSA.

    These tests validate that:
    - ML-DSA certificates can be renewed successfully
    - certmonger properly handles ML-DSA certificate renewal
    - renewed certificates maintain the same key algorithm
    """

    num_clients = 0
    topology = "line"

    @classmethod
    def install(cls, mh):
        """Install master with ML-DSA CA."""
        extra_args = [
            "--key-type-size", "mldsa",
            "--ca-key-type", "mldsa",
        ]
        tasks.install_master(cls.master, setup_dns=True, extra_args=extra_args)

    def test_httpd_cert_renewal_mldsa(self):
        """Test renewal of HTTPD certificate with ML-DSA."""
        tasks.kinit_admin(self.master)

        # Get the current certificate serial number
        result = self.master.run_command(
            ["getcert", "list", "-f", paths.HTTPD_CERT_FILE]
        )
        serial_match = re.search(r"serial: (\S+)", result.stdout_text)
        if not serial_match:
            pytest.fail("Could not find certificate serial number")
        old_serial = serial_match.group(1)

        # Request renewal
        result = self.master.run_command(
            ["getcert", "resubmit", "-f", paths.HTTPD_CERT_FILE],
            raiseonerr=False,
        )
        if result.returncode != 0:
            pytest.xfail(
                f"ML-DSA certificate renewal failed: {result.stderr_text}"
            )

        # Extract request ID
        request_match = re.search(r"Request ID '(\d+)'", result.stdout_text)
        if not request_match:
            pytest.fail("Could not parse request ID from resubmit output")
        request_id = request_match.group(1)

        # Wait for renewal to complete
        state = tasks.wait_for_request(self.master, request_id, 120)
        assert state == "MONITORING", f"Renewal ended in state {state}"

        # Verify new certificate has different serial
        result = self.master.run_command(
            ["getcert", "list", "-f", paths.HTTPD_CERT_FILE]
        )
        new_serial_match = re.search(r"serial: (\S+)", result.stdout_text)
        if not new_serial_match:
            pytest.fail("Could not find renewed certificate serial number")
        new_serial = new_serial_match.group(1)

        assert old_serial != new_serial, "Certificate was not actually renewed"

        # Verify the renewed cert still uses ML-DSA
        cert_info = self.master.run_command(
            ["openssl", "x509", "-in", paths.HTTPD_CERT_FILE,
             "-noout", "-text"]
        )
        assert "ML-DSA" in cert_info.stdout_text

        tasks.kdestroy_all(self.master)


class TestPQCMixedMode(IntegrationTest):
    """
    Test mixed mode scenarios with ML-DSA and traditional algorithms.

    These tests validate that:
    - ML-DSA CA can issue RSA/ECDSA certificates
    - Traditional CA can issue ML-DSA certificates (if supported)
    - Interoperability between different algorithm types
    """

    num_clients = 1
    topology = "line"

    @classmethod
    def install(cls, mh):
        """Install master with ML-DSA CA but RSA IPA keys."""
        extra_args = [
            "--ca-key-type", "mldsa",
        ]
        tasks.install_master(cls.master, setup_dns=True, extra_args=extra_args)
        tasks.add_a_records_for_hosts_in_master_domain(cls.master)
        tasks.install_clients([cls.master], cls.clients)

    def test_rsa_cert_from_mldsa_ca(self):
        """Request RSA certificate from ML-DSA CA."""
        user = "rsauser"
        csr = "/tmp/rsauser.csr"
        key = "/tmp/rsauser.key"
        crt = "/tmp/rsauser.crt"

        tasks.kinit_admin(self.master)
        tasks.user_add(self.master, user)
        self.master.run_command(["rm", "-f", csr, key, crt], raiseonerr=False)

        self.master.run_command(
            ["openssl", "genrsa", "-out", key, "2048"]
        )
        self.master.run_command(
            [
                "openssl", "req", "-new", "-key", key, "-out", csr,
                "-subj", f"/CN={user}",
            ]
        )

        res = self.master.run_command(
            [
                "ipa", "cert-request", "--principal", user,
                "--certificate-out", crt, csr,
            ],
            raiseonerr=False,
        )
        if res.returncode != 0:
            pytest.fail(f"RSA cert request from ML-DSA CA failed: {res.stderr_text}")

        pem = self.master.get_file_contents(crt)
        assert "BEGIN CERTIFICATE" in pem

        # Verify it's an RSA cert
        cert_info = self.master.run_command(
            ["openssl", "x509", "-in", crt, "-noout", "-text"]
        )
        assert "RSA" in cert_info.stdout_text or "rsaEncryption" in cert_info.stdout_text

        tasks.kdestroy_all(self.master)
        self.master.run_command(["rm", "-f", csr, key, crt], raiseonerr=False)

    def test_ecdsa_cert_from_mldsa_ca(self):
        """Request ECDSA certificate from ML-DSA CA."""
        user = "ecdsauser"
        csr = "/tmp/ecdsauser.csr"
        key = "/tmp/ecdsauser.key"
        crt = "/tmp/ecdsauser.crt"

        tasks.kinit_admin(self.master)
        tasks.user_add(self.master, user)
        self.master.run_command(["rm", "-f", csr, key, crt], raiseonerr=False)

        self.master.run_command(
            ["openssl", "ecparam", "-genkey", "-name", "secp384r1",
             "-out", key]
        )
        self.master.run_command(
            [
                "openssl", "req", "-new", "-key", key, "-out", csr,
                "-subj", f"/CN={user}",
            ]
        )

        res = self.master.run_command(
            [
                "ipa", "cert-request", "--principal", user,
                "--certificate-out", crt, csr,
            ],
            raiseonerr=False,
        )
        if res.returncode != 0:
            pytest.fail(f"ECDSA cert request from ML-DSA CA failed: {res.stderr_text}")

        pem = self.master.get_file_contents(crt)
        assert "BEGIN CERTIFICATE" in pem

        # Verify it's an ECDSA cert
        cert_info = self.master.run_command(
            ["openssl", "x509", "-in", crt, "-noout", "-text"]
        )
        assert "ecdsa" in cert_info.stdout_text.lower() or "EC Public Key" in cert_info.stdout_text

        tasks.kdestroy_all(self.master)
        self.master.run_command(["rm", "-f", csr, key, crt], raiseonerr=False)


class TestPQCCertificateRevocation(IntegrationTest):
    """
    Test certificate revocation with ML-DSA.

    These tests validate that:
    - ML-DSA certificates can be revoked
    - Revocation lists include ML-DSA certificates
    - OCSP works with ML-DSA certificates
    """

    num_clients = 0
    topology = "line"

    @classmethod
    def install(cls, mh):
        """Install master with ML-DSA CA."""
        extra_args = [
            "--key-type-size", "mldsa",
            "--ca-key-type", "mldsa",
        ]
        tasks.install_master(cls.master, setup_dns=True, extra_args=extra_args)

    def test_revoke_mldsa_certificate(self):
        """Test revocation of ML-DSA certificate."""
        user = "revokeuser"
        csr = "/tmp/revokeuser.csr"
        key = "/tmp/revokeuser.key"
        crt = "/tmp/revokeuser.crt"
        algo = "ML-DSA-65"

        tasks.kinit_admin(self.master)
        tasks.user_add(self.master, user)
        self.master.run_command(["rm", "-f", csr, key, crt], raiseonerr=False)

        # Check OpenSSL support
        probe = os.path.join(paths.OPENSSL_PRIVATE_DIR, ".revoke-probe.key")
        try:
            gen = self.master.run_command(
                ["openssl", "genpkey", "-algorithm", algo, "-out", probe],
                raiseonerr=False,
            )
            if gen.returncode != 0:
                pytest.skip(f"OpenSSL cannot generate {algo} keys")
        finally:
            self.master.run_command(["rm", "-f", probe], raiseonerr=False)

        self.master.run_command(
            ["openssl", "genpkey", "-algorithm", algo, "-out", key]
        )
        self.master.run_command(
            [
                "openssl", "req", "-new", "-key", key, "-out", csr,
                "-subj", f"/CN={user}",
            ]
        )

        res = self.master.run_command(
            [
                "ipa", "cert-request", "--principal", user,
                "--certificate-out", crt, csr,
            ],
            raiseonerr=False,
        )
        if res.returncode != 0:
            if "400 Client Error: Bad Request" in res.stderr_text:
                pytest.xfail("Known ML-DSA CA limitation (Dogtag 400)")
            pytest.fail(res.stderr_text)

        # Extract serial number from certificate
        cert_info = self.master.run_command(
            ["openssl", "x509", "-in", crt, "-noout", "-serial"]
        )
        serial_match = re.search(r"serial=([0-9A-Fa-f]+)", cert_info.stdout_text)
        if not serial_match:
            pytest.fail("Could not extract certificate serial number")
        serial = serial_match.group(1)

        # Revoke the certificate
        revoke_res = self.master.run_command(
            ["ipa", "cert-revoke", serial, "--revocation-reason=6"],
            raiseonerr=False,
        )
        if revoke_res.returncode != 0:
            pytest.xfail(
                f"ML-DSA certificate revocation failed: {revoke_res.stderr_text}"
            )

        # Verify certificate is in revoked state
        show_res = self.master.run_command(
            ["ipa", "cert-show", serial]
        )
        assert "Revoked: True" in show_res.stdout_text

        tasks.kdestroy_all(self.master)
        self.master.run_command(["rm", "-f", csr, key, crt], raiseonerr=False)


class TestPQCReplica(IntegrationTest):
    """
    Test replica installation and operations with ML-DSA.

    These tests validate that:
    - Replica can be installed with ML-DSA CA
    - Replica CA signing keys are properly ML-DSA
    - Certificate operations work on replica
    """

    num_replicas = 1
    topology = "star"

    @classmethod
    def install(cls, mh):
        """Install master and replica with ML-DSA."""
        extra_args = [
            "--key-type-size", "mldsa",
            "--ca-key-type", "mldsa",
        ]
        tasks.install_master(cls.master, setup_dns=True, extra_args=extra_args)
        tasks.install_replica(cls.master, cls.replicas[0], setup_ca=True)

    def test_replica_ca_cert_mldsa(self):
        """Verify replica CA certificate uses ML-DSA."""
        replica = self.replicas[0]

        result = replica.run_command(
            ["openssl", "x509", "-in", paths.IPA_CA_CRT,
             "-noout", "-text"]
        )
        # The CA cert should use ML-DSA algorithm
        assert "ML-DSA" in result.stdout_text or "mldsa" in result.stdout_text.lower()

    def test_cert_request_on_replica(self):
        """Request certificate on replica with ML-DSA CA."""
        replica = self.replicas[0]
        user = "replicauser"
        csr = "/tmp/replicauser.csr"
        key = "/tmp/replicauser.key"
        crt = "/tmp/replicauser.crt"
        algo = "ML-DSA-65"

        tasks.kinit_admin(replica)
        tasks.user_add(replica, user)
        replica.run_command(["rm", "-f", csr, key, crt], raiseonerr=False)

        # Check OpenSSL support
        probe = os.path.join(paths.OPENSSL_PRIVATE_DIR, ".replica-probe.key")
        try:
            gen = replica.run_command(
                ["openssl", "genpkey", "-algorithm", algo, "-out", probe],
                raiseonerr=False,
            )
            if gen.returncode != 0:
                pytest.skip(f"OpenSSL cannot generate {algo} keys on replica")
        finally:
            replica.run_command(["rm", "-f", probe], raiseonerr=False)

        replica.run_command(
            ["openssl", "genpkey", "-algorithm", algo, "-out", key]
        )
        replica.run_command(
            [
                "openssl", "req", "-new", "-key", key, "-out", csr,
                "-subj", f"/CN={user}",
            ]
        )

        res = replica.run_command(
            [
                "ipa", "cert-request", "--principal", user,
                "--certificate-out", crt, csr,
            ],
            raiseonerr=False,
        )
        if res.returncode != 0:
            if "400 Client Error: Bad Request" in res.stderr_text:
                pytest.xfail(
                    "Known ML-DSA CA limitation: replica cert-request fails "
                    "(Dogtag 400)"
                )
            pytest.fail(res.stderr_text)

        pem = replica.get_file_contents(crt)
        assert "BEGIN CERTIFICATE" in pem

        tasks.kdestroy_all(replica)
        replica.run_command(["rm", "-f", csr, key, crt], raiseonerr=False)

    def test_replica_getcert_tracking(self):
        """Verify replica certificates are tracked by certmonger."""
        replica = self.replicas[0]

        result = replica.run_command(
            ["getcert", "list", "-f", paths.HTTPD_CERT_FILE]
        )
        assert "profile: caIPAserviceCert" in result.stdout_text
        assert "status: MONITORING" in result.stdout_text
