"""AWS collector: Lambda customer-key environments and versions, Glue (opt-in), RDS parameter groups, exposure facts.

Recorded responses go through botocore's Stubber, which validates every response (and the request parameters we pin,
such as HidePassword=True) against the real AWS service model, so a fixture with the wrong shape fails the test.
Response shapes follow the API references: Lambda ListFunctions / FunctionConfiguration / EnvironmentError
(https://docs.aws.amazon.com/lambda/latest/api/API_ListFunctions.html), Glue GetConnections / Connection /
DataCatalogEncryptionSettings (https://docs.aws.amazon.com/glue/latest/webapi/API_GetConnections.html,
API_Connection.html), RDS DescribeDBInstances / DescribeDBParameters / DescribeDBClusters, ELB / ELBv2
DescribeLoadBalancers, API Gateway GetDomainNames, EKS DescribeCluster.  The text of a real Lambda
Environment.Error message is not documented; the AWS lab records it (see the lab README).  No network.

    cd backend && PYTHONPATH=.. .venv/bin/python -m pytest tests/test_cbom_aws_collect_wp4.py -q
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import botocore.session  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402
from botocore.stub import Stubber  # noqa: E402

from backend.utilities.cbom_sources import aws_collect  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402

REGION, ACCOUNT = "ap-south-1", "123456789012"
CMK = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/1234abcd-12ab-34cd-56ef-1234567890ab"
_BS = botocore.session.get_session()
DB_PASSWORD = "Glue-Inline-Pa55word-9182"


class _Denied:
    """Any service a test does not stub answers AccessDenied (its coverage rows are filtered out by the tests)."""

    def __getattr__(self, method):
        def denied(*_a, **_k):
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "stub"}}, method)
        if method == "get_paginator":
            return lambda *_a, **_k: type("P", (), {"paginate": denied})()
        return denied


class _Acct:
    account = ACCOUNT

    def __init__(self, plan: dict[str, list[tuple]]):
        self.clients, self.stubs = {}, []
        for service, calls in plan.items():
            client = _BS.create_client(service, region_name=REGION, aws_access_key_id="x", aws_secret_access_key="y")
            stub = Stubber(client)
            for method, response, params in calls:
                if isinstance(response, str):
                    stub.add_client_error(method, service_error_code=response, http_status_code=403)
                else:
                    stub.add_response(method, response, params)
            stub.activate()
            self.clients[service], self.stubs = client, self.stubs + [stub]

    def client(self, service, _region):
        return self.clients.get(service) or _Denied()


def _run(plan, opts=None):
    acct = _Acct(plan)
    found: list[dict] = []
    rows = aws_collect._region_services(acct, REGION, f"aws:{ACCOUNT}", found.append, opts or {})
    for stub in acct.stubs:
        stub.assert_no_pending_responses()  # every recorded call was made, in order, with the pinned parameters
    services = {svc: status for svc, status, _d in rows}
    # drop the whole-service "denied" rows of the services this test did not stub
    unstubbed = {f"{svc} in {REGION}" for svc, status in services.items() if status == "denied"}
    return services, [a for a in found if not (a["type"] == "coverage" and a["facts"]["check"] in unstubbed)]


def _fn(name, version="$LATEST", env=None, kms=None):
    arn = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{name}" + (f":{version}" if version != "$LATEST" else "")
    out = {"FunctionName": name, "FunctionArn": arn, "Runtime": "python3.12", "Role": f"arn:aws:iam::{ACCOUNT}:role/fn",
           "Handler": "app.handler", "CodeSize": 1024, "Timeout": 3, "MemorySize": 128,
           "LastModified": "2026-10-30T10:00:00.000+0000", "Version": version}
    if env is not None:
        out["Environment"] = env
    if kms:
        out["KMSKeyArn"] = kms
    return out


# ----------------------------------------------------------------------------- Lambda
CMK_ERROR = {"Error": {"ErrorCode": "AccessDeniedException",
                       "Message": "Lambda was unable to decrypt the environment variables because KMS access was denied."}}


def test_customer_key_environment_with_the_switch_off_is_a_coverage_row_that_says_how_to_inspect_it():
    plan = {"lambda": [("list_functions", {"Functions": [
        _fn("payments", env=CMK_ERROR, kms=CMK),
        _fn("billing", env={"Variables": {"DB_PASSWORD": "Billing-Plain-Pass-11", "LOG_LEVEL": "info"}}),
        _fn("billing", version="3", env={"Variables": {"DB_PASSWORD": "Billing-Plain-Pass-11"}}),
    ]}, {"FunctionVersion": "ALL"})]}
    services, found = _run(plan)
    assert services["lambda"] == "ok"
    gap = next(a for a in found if a["type"] == "coverage")
    assert gap["facts"]["status"] == "denied" and gap["facts"]["kms_key_id"] == CMK
    assert "Decrypt Lambda environments under customer-managed keys" in gap["facts"]["detail"]
    secrets = [a for a in found if a["type"] == "cloud_secret"]
    # $LATEST and the published version 3 are separate rows (each version keeps its own environment)
    assert sorted(a["location"].rsplit(":", 1)[-1] for a in secrets) == ["3#environment/DB_PASSWORD", "billing#environment/DB_PASSWORD"]
    assert all(a["facts"]["customer_managed_key"] is False for a in secrets)
    assert "Billing-Plain-Pass-11" not in repr(found)


def test_customer_key_environment_with_the_switch_on_is_read_and_a_denial_names_the_key_policy():
    plan = {"lambda": [("list_functions", {"Functions": [
        _fn("payments", env={"Variables": {"API_TOKEN": "tok-8f2a9c71e4b0d3a6"}}, kms=CMK),
        _fn("ledger", env=CMK_ERROR, kms=CMK),
    ]}, {"FunctionVersion": "ALL"})]}
    _s, found = _run(plan, {"decrypt_lambda_cmk": True})
    secret = next(a for a in found if a["type"] == "cloud_secret")
    assert secret["facts"]["kms_key_id"] == CMK and secret["facts"]["customer_managed_key"] is True
    assert classify("cloud_secret", None, None, None, secret["facts"])["finding_codes"] == ["SECRET_IN_CONFIG"]
    gap = next(a for a in found if a["type"] == "coverage")
    assert "key policy" in gap["facts"]["detail"] and "tok-8f2a9c71e4b0d3a6" not in repr(found)


def test_zero_functions():
    services, found = _run({"lambda": [("list_functions", {"Functions": []}, {"FunctionVersion": "ALL"})]})
    assert services["lambda"] == "ok" and not [a for a in found if "lambda" in a["location"]]


def test_301_function_versions_hit_the_cap_and_say_so():
    pages = []
    for page in range(7):  # 7 pages of 43 = 301
        functions = [_fn(f"fn-{page}-{i}", env={"Variables": {"MODE": "x"}}) for i in range(43)]
        response = {"Functions": functions, **({"NextMarker": f"m{page + 1}"} if page < 6 else {})}
        params = {"FunctionVersion": "ALL", **({"Marker": f"m{page}"} if page else {})}
        pages.append(("list_functions", response, params))
    services, found = _run({"lambda": pages})
    cap = [a for a in found if a["type"] == "coverage" and a["facts"]["status"] == "truncated"]
    assert services["lambda"] == "ok" and len(cap) == 1 and "300" in cap[0]["facts"]["detail"]


def test_exactly_300_function_versions_are_complete():
    pages = []
    for page in range(6):  # 6 pages of 50 = 300, no further page
        response = {"Functions": [_fn(f"fn-{page}-{i}") for i in range(50)], **({"NextMarker": f"m{page + 1}"} if page < 5 else {})}
        pages.append(("list_functions", response, {"FunctionVersion": "ALL", **({"Marker": f"m{page}"} if page else {})}))
    _s, found = _run({"lambda": pages})
    assert not [a for a in found if a["type"] == "coverage" and a["facts"]["status"] == "truncated"]


def test_a_region_that_is_not_enabled_is_reported_as_such():
    services = {}
    acct = _Acct({})

    class NotEnabled(_Denied):
        def __getattr__(self, method):
            def fail(*_a, **_k):
                raise ClientError({"Error": {"Code": "UnrecognizedClientException", "Message": "stub"}}, method)
            return (lambda *_a, **_k: type("P", (), {"paginate": fail})()) if method == "get_paginator" else fail

    acct.client = lambda _s, _r: NotEnabled()  # type: ignore[method-assign]
    found: list[dict] = []
    rows = aws_collect._region_services(acct, "me-central-1", f"aws:{ACCOUNT}", found.append, {})
    services = {svc: status for svc, status, _d in rows}
    assert set(services.values()) == {"not_enabled"} and "glue" in services and "elb-classic" in services
    assert all(a["type"] == "coverage" and a["facts"]["status"] == "not_enabled" for a in found)


# ----------------------------------------------------------------------------- Glue
CATALOG_OFF = {"DataCatalogEncryptionSettings": {"EncryptionAtRest": {"CatalogEncryptionMode": "DISABLED"},
                                                 "ConnectionPasswordEncryption": {"ReturnConnectionPasswordEncrypted": False}}}
CATALOG_ON = {"DataCatalogEncryptionSettings": {
    "EncryptionAtRest": {"CatalogEncryptionMode": "SSE-KMS", "SseAwsKmsKeyId": CMK},
    "ConnectionPasswordEncryption": {"ReturnConnectionPasswordEncrypted": True, "AwsKmsKeyId": CMK}}}
NOW = dt.datetime(2026, 10, 30, tzinfo=dt.timezone.utc)


def _glue_plan(settings, connections, *, read=True):
    calls = [
        ("get_data_catalog_encryption_settings", settings, {}),
        ("get_security_configurations", {"SecurityConfigurations": [{
            "Name": "etl-kms", "CreatedTimeStamp": NOW, "EncryptionConfiguration": {
                "S3Encryption": [{"S3EncryptionMode": "SSE-KMS", "KmsKeyArn": CMK}],
                "CloudWatchEncryption": {"CloudWatchEncryptionMode": "DISABLED"},
                "JobBookmarksEncryption": {"JobBookmarksEncryptionMode": "CSE-KMS", "KmsKeyArn": CMK}}}]}, {}),
        ("get_jobs", {"Jobs": [
            {"Name": "nightly", "Role": "glue-role", "Command": {"Name": "glueetl"}, "SecurityConfiguration": "etl-kms",
             "DefaultArguments": {"--db_password": "never-kept-123456"}},
            {"Name": "adhoc", "Role": "glue-role", "Command": {"Name": "pythonshell"}}]}, {}),
        ("get_databases", {"DatabaseList": [{"Name": "sales"}]}, {"MaxResults": 1}),
    ]
    if read:
        calls.append(("get_connections", {"ConnectionList": connections}, {"HidePassword": True}))
    return {"glue": calls}


INLINE = {"Name": "orders-pg", "ConnectionType": "JDBC", "ConnectionProperties": {
    "JDBC_CONNECTION_URL": "jdbc:postgresql://orders.cluster-abc.ap-south-1.rds.amazonaws.com:5432/orders?user=etl&password=" + DB_PASSWORD,
    "USERNAME": "etl", "PASSWORD": DB_PASSWORD, "JDBC_ENFORCE_SSL": "false"}}
WITH_SECRET = {"Name": "crm-mysql", "ConnectionType": "JDBC", "ConnectionProperties": {
    "JDBC_CONNECTION_URL": "jdbc:mysql://crm.internal:3306/crm", "SECRET_ID": "prod/crm/etl", "JDBC_ENFORCE_SSL": "true",
    "CUSTOM_JDBC_CERT": "s3://certs/rds-ca.pem"}}
KAFKA = {"Name": "events", "ConnectionType": "KAFKA", "ConnectionProperties": {
    "KAFKA_BOOTSTRAP_SERVERS": "b-1.events:9092", "KAFKA_SSL_ENABLED": "false"}}


def test_glue_inline_password_with_catalog_encryption_off():
    services, found = _run(_glue_plan(CATALOG_OFF, [INLINE, WITH_SECRET, KAFKA]), {"read_glue": True})
    assert services["glue"] == "ok"
    conns = {a["name"]: a for a in found if a["type"] == "glue_connection"}
    inline = conns["Glue connection orders-pg"]
    assert inline["facts"]["password_storage"] == "plaintext" and inline["facts"]["has_password_key"] is True
    assert inline["facts"]["jdbc_url"] == "jdbc:postgresql://orders.cluster-abc.ap-south-1.rds.amazonaws.com:5432/orders"
    codes = classify("glue_connection", None, None, None, inline["facts"])["finding_codes"]
    assert codes == ["GLUE_PLAINTEXT_PASSWORD", "GLUE_JDBC_NO_TLS"]
    secret = conns["Glue connection crm-mysql"]
    assert secret["facts"]["password_storage"] == "secrets_manager" and secret["facts"]["has_custom_jdbc_cert"] is True
    assert classify("glue_connection", None, None, None, secret["facts"])["finding_codes"] == []
    kafka = conns["Glue connection events"]
    assert classify("glue_connection", None, None, None, kafka["facts"])["finding_codes"] == ["NO_TLS"]
    catalog = next(a for a in found if a["type"] == "glue_catalog")
    assert catalog["facts"]["jobs_without_security_configuration"] == 1 and catalog["facts"]["connections"] == 3
    assert classify("glue_catalog", None, None, None, catalog["facts"])["finding_codes"] == ["GLUE_CATALOG_UNENCRYPTED"]
    config = next(a for a in found if a["type"] == "storage_encryption")
    assert config["facts"]["encrypted"] is True and config["facts"]["jobs_using"] == 1
    for secret_text in (DB_PASSWORD, "never-kept-123456", "user=etl"):  # nothing but allow-listed facts leaves
        assert secret_text not in repr(found)


def test_glue_password_encrypted_when_catalog_password_encryption_is_on():
    encrypted = {"Name": "orders-pg", "ConnectionType": "JDBC", "ConnectionProperties": {
        "JDBC_CONNECTION_URL": "jdbc:postgresql://orders:5432/orders?sslmode=verify-full", "USERNAME": "etl",
        "ENCRYPTED_PASSWORD": "AQICAHh...base64...", "JDBC_ENFORCE_SSL": "false"}}
    _s, found = _run(_glue_plan(CATALOG_ON, [encrypted]), {"read_glue": True})
    conn = next(a for a in found if a["type"] == "glue_connection")
    assert conn["facts"]["password_storage"] == "encrypted" and conn["facts"]["jdbc_url_requests_tls"] is True
    assert classify("glue_connection", None, None, None, conn["facts"])["finding_codes"] == []
    catalog = next(a for a in found if a["type"] == "glue_catalog")
    assert classify("glue_catalog", None, None, None, catalog["facts"])["finding_codes"] == []


def test_glue_password_state_unknown_is_never_reported_as_encrypted():
    """Catalog encryption on now, no password key visible (HidePassword) and no ENCRYPTED_PASSWORD: the connection may
    predate the setting, so its state is unknown -- neither a finding nor 'encrypted'."""
    hidden = {"Name": "legacy", "ConnectionType": "JDBC", "ConnectionProperties": {
        "JDBC_CONNECTION_URL": "jdbc:postgresql://legacy:5432/x", "USERNAME": "etl", "JDBC_ENFORCE_SSL": "true"}}
    network = {"Name": "vpc-only", "ConnectionType": "NETWORK", "ConnectionProperties": {}}
    _s, found = _run(_glue_plan(CATALOG_ON, [hidden, network]), {"read_glue": True})
    conns = {a["name"]: a["facts"] for a in found if a["type"] == "glue_connection"}
    assert conns["Glue connection legacy"]["password_storage"] == "unknown"
    assert conns["Glue connection vpc-only"]["password_storage"] == "none"
    assert all(classify("glue_connection", None, None, None, f)["finding_codes"] == [] for f in conns.values())


def test_glue_switch_off_never_calls_get_connections():
    services, found = _run(_glue_plan(CATALOG_OFF, [], read=False), {})
    assert services["glue"] == "ok" and not [a for a in found if a["type"] == "glue_connection"]
    catalog = next(a for a in found if a["type"] == "glue_catalog")
    assert catalog["facts"]["connections_read"] is False and catalog["facts"]["connections"] is None


@pytest.mark.parametrize("url,expected,tls", [
    ("jdbc:mysql://admin:S3cret!@db.example.com:3306/app?useSSL=false", "jdbc:mysql://db.example.com:3306/app", False),
    ("jdbc:sqlserver://sql.example.com:1433;databaseName=x;user=sa;password=S3cret!;encrypt=true", "jdbc:sqlserver://sql.example.com:1433", True),
    ("jdbc:oracle:thin:scott/tiger@db.example.com:1521/ORCL", "jdbc:oracle://db.example.com:1521/ORCL", False),
    ("jdbc:oracle:thin:@(DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST=ora.example.com)(PORT=2484))(CONNECT_DATA=(SERVICE_NAME=s)))",
     "jdbc:oracle://ora.example.com:2484", True),
    ("jdbc:redshift://rs.example.com:5439/dev?ssl=true&password=x", "jdbc:redshift://rs.example.com:5439/dev", True),
    ("not a jdbc url", None, False),
])
def test_jdbc_url_keeps_host_port_database_only(url, expected, tls):
    stripped, requests_tls = aws_collect._strip_jdbc_url(url)
    assert stripped == expected and requests_tls is tls
    assert "S3cret" not in str(stripped) and "tiger" not in str(stripped)


# ----------------------------------------------------------------------------- RDS parameters and exposure
def _db(identifier, engine, group, *, public, cluster=None):
    out = {"DBInstanceIdentifier": identifier, "DBInstanceArn": f"arn:aws:rds:{REGION}:{ACCOUNT}:db:{identifier}",
           "Engine": engine, "EngineVersion": "15.7", "StorageEncrypted": True, "PubliclyAccessible": public,
           "Endpoint": {"Address": f"{identifier}.abc.{REGION}.rds.amazonaws.com", "Port": 5432},
           "DBParameterGroups": [{"DBParameterGroupName": group, "ParameterApplyStatus": "in-sync"}],
           "CACertificateIdentifier": "rds-ca-rsa2048-g1"}
    if cluster:
        out["DBClusterIdentifier"] = cluster
    return out


def _params(values: dict[str, str]):
    return {"Parameters": [{"ParameterName": k, "ParameterValue": v, "Source": "user", "ApplyType": "dynamic",
                            "DataType": "string", "IsModifiable": True} for k, v in values.items()]
            + [{"ParameterName": "work_mem", "ParameterValue": "4096", "Source": "engine-default"}]}


def test_rds_postgres_parameters_md5_accepted_and_force_ssl_off():
    plan = {"rds": [
        ("describe_db_instances", {"DBInstances": [_db("ledger", "postgres", "zs-lab-pg15", public=True)]}, {}),
        ("describe_db_parameters", _params({"password_encryption": "md5", "rds.force_ssl": "0",
                                            "rds.accepted_password_auth_method": "md5+scram"}),
         {"DBParameterGroupName": "zs-lab-pg15"}),
    ]}
    _s, found = _run(plan)
    config = next(a for a in found if a["type"] == "database_config")
    facts = config["facts"]
    assert facts["endpoint"] == f"ledger.abc.{REGION}.rds.amazonaws.com:5432" and facts["internet_facing"] is True
    assert facts["exposure_basis"] == "RDS PubliclyAccessible=true" and "work_mem" not in facts["parameters"]
    verdict = classify("database_config", None, None, None, facts)
    assert set(verdict["finding_codes"]) == {"DB_TLS_OPTIONAL", "DB_MD5_DEFAULT", "DB_MD5_ACCEPTED"}
    storage = next(a for a in found if a["type"] == "storage_encryption")
    assert storage["facts"]["internet_facing"] is True and storage["facts"]["endpoint"] == facts["endpoint"]


def test_aurora_cluster_parameters_win_and_scram_only_is_clean():
    plan = {"rds": [
        ("describe_db_instances", {"DBInstances": [_db("aur-1", "aurora-postgresql", "default.aurora-postgresql15",
                                                       public=False, cluster="aur")]}, {}),
        ("describe_db_clusters", {"DBClusters": [{"DBClusterIdentifier": "aur", "DBClusterParameterGroup": "zs-aur-15",
                                                  "Engine": "aurora-postgresql"}]}, {}),
        ("describe_db_parameters", _params({"rds.force_ssl": "0"}), {"DBParameterGroupName": "default.aurora-postgresql15"}),
        ("describe_db_cluster_parameters", _params({"rds.force_ssl": "1", "password_encryption": "scram-sha-256",
                                                    "rds.accepted_password_auth_method": "scram"}),
         {"DBClusterParameterGroupName": "zs-aur-15"}),
    ]}
    _s, found = _run(plan)
    facts = next(a for a in found if a["type"] == "database_config")["facts"]
    assert facts["require_secure_transport"] is True and facts["md5_auth_accepted"] is False and facts["internet_facing"] is False
    assert classify("database_config", None, None, None, facts)["finding_codes"] == []


def test_rds_parameter_group_denied_is_a_coverage_row_not_silence():
    plan = {"rds": [
        ("describe_db_instances", {"DBInstances": [_db("ledger", "mysql", "mysql80", public=False)]}, {}),
        ("describe_db_parameters", "AccessDenied", None),
    ]}
    services, found = _run(plan)
    assert services["rds"] == "ok"
    gap = next(a for a in found if a["type"] == "coverage")
    assert gap["location"].endswith("#parameters") and gap["facts"]["status"] == "denied"
    assert not [a for a in found if a["type"] == "database_config"]


def test_exposure_facts_for_load_balancers_api_gateway_and_eks():
    lb_arn = f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/app/web/1"
    plan = {
        "elbv2": [
            ("describe_load_balancers", {"LoadBalancers": [{"LoadBalancerArn": lb_arn, "LoadBalancerName": "web",
                                                            "Scheme": "internet-facing", "Type": "application"}]}, {}),
            ("describe_listeners", {"Listeners": [{"ListenerArn": lb_arn + "/l1", "Port": 80, "Protocol": "HTTP"}]},
             {"LoadBalancerArn": lb_arn}),
        ],
        "elb": [
            ("describe_load_balancers", {"LoadBalancerDescriptions": [{
                "LoadBalancerName": "legacy", "Scheme": "internal", "ListenerDescriptions": [{
                    "Listener": {"Protocol": "HTTPS", "LoadBalancerPort": 443, "InstanceProtocol": "HTTP", "InstancePort": 80,
                                 "SSLCertificateId": f"arn:aws:acm:{REGION}:{ACCOUNT}:certificate/c1"},
                    "PolicyNames": ["ELBSecurityPolicy-2016-08"]}]}]}, {}),
            ("describe_load_balancer_policies", {"PolicyDescriptions": [{
                "PolicyName": "ELBSecurityPolicy-2016-08", "PolicyTypeName": "SSLNegotiationPolicyType",
                "PolicyAttributeDescriptions": [
                    {"AttributeName": "Reference-Security-Policy", "AttributeValue": "ELBSecurityPolicy-2016-08"},
                    {"AttributeName": "Protocol-TLSv1", "AttributeValue": "true"},
                    {"AttributeName": "Protocol-TLSv1.2", "AttributeValue": "true"},
                    {"AttributeName": "Protocol-SSLv3", "AttributeValue": "false"},
                    {"AttributeName": "Server-Defined-Cipher-Order", "AttributeValue": "true"},
                    {"AttributeName": "ECDHE-RSA-AES128-GCM-SHA256", "AttributeValue": "true"},
                    {"AttributeName": "AES128-SHA", "AttributeValue": "true"},
                    {"AttributeName": "DES-CBC3-SHA", "AttributeValue": "false"}]}]},
             {"LoadBalancerName": "legacy", "PolicyNames": ["ELBSecurityPolicy-2016-08"]}),
        ],
        "apigateway": [("get_domain_names", {"items": [
            {"domainName": "api.bank.example", "securityPolicy": "TLS_1_2", "endpointConfiguration": {"types": ["REGIONAL"]}},
            {"domainName": "internal.bank.example", "securityPolicy": "TLS_1_2", "endpointConfiguration": {"types": ["PRIVATE"]}}]}, {})],
        "eks": [
            ("list_clusters", {"clusters": ["core"]}, {}),
            ("describe_cluster", {"cluster": {"name": "core", "arn": f"arn:aws:eks:{REGION}:{ACCOUNT}:cluster/core", "version": "1.30",
                                              "resourcesVpcConfig": {"endpointPublicAccess": True, "endpointPrivateAccess": True,
                                                                     "publicAccessCidrs": ["203.0.113.0/24"]}}}, {"name": "core"}),
        ],
    }
    _s, found = _run(plan)
    by_name = {a["name"]: a for a in found if a["type"] in ("load_balancer_tls", "api_tls", "storage_encryption")}
    assert by_name["web:80"]["facts"]["internet_facing"] is True and "internet-facing" in by_name["web:80"]["facts"]["exposure_basis"]
    classic = by_name["legacy:443"]["facts"]
    assert classic["internet_facing"] is False and classic["protocols"] == ["TLSv1.0", "TLSv1.2"]
    assert classic["ciphers"] == ["ECDHE-RSA-AES128-GCM-SHA256", "AES128-SHA"] and classic["static_rsa_kex"] is True
    assert {"PROTO_TLS10", "STATIC_RSA_KEX"} <= set(classify("load_balancer_tls", None, None, "HTTPS", classic)["finding_codes"])
    assert by_name["api.bank.example"]["facts"]["internet_facing"] is True
    assert by_name["internal.bank.example"]["facts"]["internet_facing"] is False
    eks = by_name["EKS core secrets"]["facts"]
    assert eks["internet_facing"] is True and "limited to 1 CIDR" in eks["exposure_basis"]


def test_ec2_exposure_reaches_volumes_and_user_data_and_cloudfront_is_always_public():
    instance = {"InstanceId": "i-0abc", "State": {"Name": "running"}, "PublicIpAddress": "203.0.113.10",
                "NetworkInterfaces": []}
    private = {"InstanceId": "i-0def", "State": {"Name": "running"}, "NetworkInterfaces": [
        {"Ipv6Addresses": [{"Ipv6Address": "2001:db8::10"}]}]}
    import base64

    plan = {"ec2": [
        ("get_ebs_encryption_by_default", {"EbsEncryptionByDefault": True}, {}),
        ("describe_volumes", {"Volumes": [
            {"VolumeId": "vol-1", "Encrypted": False, "Size": 8, "Attachments": [{"InstanceId": "i-0abc"}]},
            {"VolumeId": "vol-2", "Encrypted": True, "Size": 8, "Attachments": [{"InstanceId": "i-0def"}]}]}, {}),
        ("describe_instances", {"Reservations": [{"Instances": [instance, private]}]}, {}),
        ("describe_key_pairs", {"KeyPairs": []}, {"IncludePublicKey": True}),
        ("describe_instance_attribute", {"UserData": {"Value": base64.b64encode(b"export DB_PASSWORD='UserData-Pa55-771'\n").decode()}},
         {"InstanceId": "i-0abc", "Attribute": "userData"}),
        ("describe_instance_attribute", {"UserData": {}}, {"InstanceId": "i-0def", "Attribute": "userData"}),
    ]}
    _s, found = _run(plan)
    volumes = {a["name"]: a["facts"] for a in found if a["type"] == "storage_encryption" and a["name"].startswith("vol-")}
    assert volumes["vol-1"]["internet_facing"] is True and volumes["vol-2"]["internet_facing"] is None
    userdata = next(a for a in found if a["type"] == "cloud_secret")
    assert userdata["facts"]["internet_facing"] is True and "UserData-Pa55-771" not in repr(found)

    class Global:
        account = ACCOUNT

        def client(self, service, _region):
            if service != "cloudfront":
                return _Denied()
            client = _BS.create_client("cloudfront", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="y")
            stub = Stubber(client)
            stub.add_response("list_distributions", {"DistributionList": {"Marker": "", "MaxItems": 100, "IsTruncated": False,
                                                                          "Quantity": 1, "Items": [_distribution()]}}, {})
            stub.activate()
            return client

    out: list[dict] = []
    aws_collect._global_services(Global(), f"aws:{ACCOUNT}", out.append)
    cdn = next(a for a in out if a["type"] == "cdn_tls")
    assert cdn["facts"]["internet_facing"] is True and "CloudFront" in cdn["facts"]["exposure_basis"]


def _distribution():
    return {"Id": "E1", "ARN": f"arn:aws:cloudfront::{ACCOUNT}:distribution/E1", "Status": "Deployed",
            "LastModifiedTime": NOW, "DomainName": "d1.cloudfront.net", "Aliases": {"Quantity": 0},
            "Origins": {"Quantity": 1, "Items": [{"Id": "o", "DomainName": "o.example.com"}]},
            "DefaultCacheBehavior": {"TargetOriginId": "o", "ViewerProtocolPolicy": "redirect-to-https"},
            "CacheBehaviors": {"Quantity": 0}, "CustomErrorResponses": {"Quantity": 0}, "Comment": "", "PriceClass": "PriceClass_All",
            "Enabled": True, "ViewerCertificate": {"CloudFrontDefaultCertificate": False, "MinimumProtocolVersion": "TLSv1.2_2021",
                                                   "ACMCertificateArn": f"arn:aws:acm:us-east-1:{ACCOUNT}:certificate/c"},
            "Restrictions": {"GeoRestriction": {"RestrictionType": "none", "Quantity": 0}}, "WebACLId": "",
            "HttpVersion": "http2", "IsIPV6Enabled": True, "Staging": False}


def test_every_wp4_finding_code_builds_into_the_knowledge_base(tmp_path):
    """crypto_kb.json is rebuilt once by the integrator; this proves the kb_ext entries build and cover every code."""
    import json
    import re
    import subprocess

    codes = set(re.findall(r'out\.add\(\s*"([A-Z0-9_]+)"',
                           (_REPO_ROOT / "backend/utilities/cbom_sources/classify_ext/cloud.py").read_text()))
    codes.add("DB_MD5_ACCEPTED")  # the database_config rule in classify.py
    out = tmp_path / "kb.json"
    subprocess.run([sys.executable, str(_REPO_ROOT / "scripts/crypto_kb/build_kb.py"), "0.0.0-test", str(out)],
                   check=True, capture_output=True, timeout=120)
    node = json.loads(out.read_text())["findings"]["node"]
    assert codes and not sorted(c for c in codes if c not in node)
    assert node["GLUE_PLAINTEXT_PASSWORD"]["default_impact"] == "High" and node["DB_MD5_ACCEPTED"]["category"] == "database"
