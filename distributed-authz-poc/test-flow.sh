#!/usr/bin/env bash
set -euo pipefail

echo "=== 1. Syncing Central ODB Topology (Jira -> Applications) to Ory Keto & OpenLDAP ==="
./cli.sh sync-odb

echo "=== 2. Minting SSO Token for User 'alice' ==="
ALICE_TOKEN=$(curl -s -X POST http://localhost:4000/token -d '{"sub":"alice","azp":"app-foo"}' | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));console.log(d.access_token)")

echo "=== 3. Verifying Alice CANNOT view Foo secrets before approval (Expect 403) ==="
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${ALICE_TOKEN}" http://localhost:4455/foo/secrets/app-foo)
echo "Pre-approval status: ${HTTP_CODE}"

echo "=== 4. Submitting Access Request for 'foo-secret' on JIRA-100 (PENDING) ==="
REQ_JSON=$(./cli.sh request-access alice foo-secret jira JIRA-100 "Need access to payment secrets")
echo "${REQ_JSON}"
REQ_ID=$(echo "${REQ_JSON}" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));console.log(d.requestId)")

echo "=== 5. Approving Request ${REQ_ID} -> Triggers Dual-Write to Ory Keto & OpenLDAP ==="
./cli.sh approve "${REQ_ID}" "security-lead"

echo "=== 6. Verifying Alice CAN view Foo & Bar secrets via Inheritance (Expect 200) ==="
curl -s -H "Authorization: Bearer ${ALICE_TOKEN}" http://localhost:4455/foo/secrets/app-foo
echo ""
curl -s -H "Authorization: Bearer ${ALICE_TOKEN}" http://localhost:4455/foo/secrets/app-bar
echo ""

echo "=== 7. Verifying Realized Group Membership in OpenLDAP ==="
docker compose exec -T openldap ldapsearch -x -H ldap://localhost -D "cn=admin,dc=internal,dc=local" -w admin -b "ou=JIRA-100,ou=resources,dc=internal,dc=local" "(cn=foo-secret)"

echo "=== 8. Verifying Policy-Based Access: Application Foo -> Bar (All APIs) ==="
curl -s http://localhost:4003/foo/call-bar
echo ""
