#!/usr/bin/env bash
set -euo pipefail

GOV_URL="${GOV_URL:-http://localhost:4002}"
CMD="${1:-help}"

case "$CMD" in
  sync-odb)
    curl -s -X POST "${GOV_URL}/sync-odb" | cat
    echo ""
    ;;
  create-template)
    # Usage: ./cli.sh create-template <templateId> <description> <ketoRelation> <ldapGroupCn>
    curl -s -X POST "${GOV_URL}/config/role-templates" \
      -H "Content-Type: application/json" \
      -d "{\"templateId\":\"$2\",\"description\":\"$3\",\"ketoRelation\":\"$4\",\"ldapGroupCn\":\"$5\"}"
    echo ""
    ;;
  request-access)
    # Usage: ./cli.sh request-access <userId> <roleTemplateId> <targetType> <targetId> [justification]
    curl -s -X POST "${GOV_URL}/requests" \
      -H "Content-Type: application/json" \
      -d "{\"userId\":\"$2\",\"roleTemplateId\":\"$3\",\"targetType\":\"$4\",\"targetId\":\"$5\",\"justification\":\"${6:-CLI request}\"}"
    echo ""
    ;;
  list-requests)
    curl -s "${GOV_URL}/requests"
    echo ""
    ;;
  approve)
    # Usage: ./cli.sh approve <requestId> [reviewedBy]
    curl -s -X POST "${GOV_URL}/requests/$2/approve" \
      -H "Content-Type: application/json" \
      -d "{\"reviewedBy\":\"${3:-cli-approver}\"}"
    echo ""
    ;;
  reject)
    # Usage: ./cli.sh reject <requestId> [reviewedBy]
    curl -s -X POST "${GOV_URL}/requests/$2/reject" \
      -H "Content-Type: application/json" \
      -d "{\"reviewedBy\":\"${3:-cli-approver}\"}"
    echo ""
    ;;
  audit)
    curl -s "${GOV_URL}/state"
    echo ""
    ;;
  *)
    echo "Usage: ./cli.sh <command> [args]"
    echo "Commands:"
    echo "  sync-odb"
    echo "  create-template <templateId> <description> <ketoRelation> <ldapGroupCn>"
    echo "  request-access <userId> <roleTemplateId> <jira|app> <targetId> [justification]"
    echo "  list-requests"
    echo "  approve <requestId> [reviewedBy]"
    echo "  reject <requestId> [reviewedBy]"
    echo "  audit"
    ;;
esac
