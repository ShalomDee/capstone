#!/bin/sh
# Collects the rules, protocol and your code files into one text file,
# so you can paste it as the first message in a web AI chat.
# Usage: scripts/ai-context.sh <carvin|chris|shalom> [extra files...]

name="$1"
case "$name" in
  carvin) own="common/securenet.h common/securenet.c common/framing.h" ;;
  chris)  own="common/identity.h common/identity.c server/handlers.h server/handlers.c client/commands.h client/commands.c common/framing.h common/securenet.h" ;;
  shalom) own="" ;;
  *) echo "usage: $0 <carvin|chris|shalom> [extra files...]" >&2; exit 1 ;;
esac
shift

out="build/ai-context-$name.txt"
mkdir -p build
{
  echo "I am $name, a teammate on the QuantumDrive project. Below are the project's rules and files."
  echo "Follow AGENTS.md and ai/role-$name.md for this whole chat. I am $name, so you do not need to ask."
  echo "You cannot see the repo; rely only on the files below and ask me to paste anything else you need."
  for f in AGENTS.md ai/rules-common.md "ai/role-$name.md" ai/glossary.md docs/PROTOCOL.md common/protocol.h $own "$@"; do
    echo
    echo "===== FILE: $f ====="
    cat "$f"
  done
} > "$out"
echo "Wrote $out ($(wc -c < "$out") bytes). Open it, select all, copy, and paste it into a new chat."
