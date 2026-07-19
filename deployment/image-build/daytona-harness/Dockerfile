FROM daytonaio/sandbox:v0.190.0-slim-amd64@sha256:91e37b087e04314e481009f9f95c98b6d882a930691deb03de6a68f774cdb16e

USER root

COPY deployment/image-build/daytona-harness/package.json deployment/image-build/daytona-harness/package-lock.json /opt/mte-harness/
RUN cd /opt/mte-harness \
    && npm ci --omit=dev --ignore-scripts --no-audit --no-fund --registry=https://registry.npmjs.org/ \
    && node ./node_modules/@anthropic-ai/claude-code/install.cjs \
    && ln -s /opt/mte-harness/node_modules/.bin/codex /usr/local/bin/codex \
    && ln -s /opt/mte-harness/node_modules/.bin/claude /usr/local/bin/claude \
    && ln -s /opt/mte-harness/node_modules/.bin/pi /usr/local/bin/pi

# Supply-chain bindings: MTE_JQ_VERSION/MTE_JQ_LINUX_AMD64_SHA256,
# MTE_TOOLHIVE_VERSION/MTE_TOOLHIVE_ARCHIVE_SHA256, and
# MTE_GITHUB_CLI_VERSION/MTE_GITHUB_CLI_ARCHIVE_SHA256.
RUN set -eux; \
    curl -fsSL -o /tmp/jq https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-linux-amd64; \
    echo '020468de7539ce70ef1bceaf7cde2e8c4f2ca6c3afb84642aabc5c97d9fc2a0d  /tmp/jq' | sha256sum -c -; \
    install -m 0755 /tmp/jq /usr/local/bin/jq; \
    curl -fsSL -o /tmp/toolhive.tar.gz https://github.com/stacklok/toolhive/releases/download/v0.36.0/toolhive_0.36.0_linux_amd64.tar.gz; \
    echo 'ca87b9d9eec394d953868a8fbbbda88d7c6105ac65c1a45327b7af75bfcfbce9  /tmp/toolhive.tar.gz' | sha256sum -c -; \
    tar -xzf /tmp/toolhive.tar.gz -C /tmp thv; \
    install -m 0755 /tmp/thv /usr/local/bin/thv; \
    curl -fsSL -o /tmp/gh.tar.gz https://github.com/cli/cli/releases/download/v2.96.0/gh_2.96.0_linux_amd64.tar.gz; \
    echo '83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60  /tmp/gh.tar.gz' | sha256sum -c -; \
    tar -xzf /tmp/gh.tar.gz -C /tmp; \
    install -m 0755 /tmp/gh_2.96.0_linux_amd64/bin/gh /usr/local/bin/gh; \
    rm -rf /tmp/jq /tmp/thv /tmp/toolhive.tar.gz /tmp/gh.tar.gz /tmp/gh_2.96.0_linux_amd64

COPY deployment/agent-runtime/pi/mte-toolhive.js /home/daytona/.pi/mte-profile/extensions/mte-toolhive.js
COPY deployment/image-build/daytona-harness/pi-models.json /home/daytona/.pi/mte-profile/models.json
COPY deployment/image-build/daytona-harness/pi-settings.json /home/daytona/.pi/mte-profile/settings.json
COPY deployment/image-build/daytona-harness/managed-mcp.json /etc/claude-code/managed-mcp.json
COPY skills/verification-before-completion/SKILL.md /opt/mte-skill/SKILL.md
COPY skills/verification-before-completion/agents/openai.yaml /opt/mte-skill/agents/openai.yaml

RUN set -eux; \
    install -d -o daytona -g daytona -m 0755 /home/daytona/paperclip-workspace; \
    for destination in \
      /home/daytona/.agents/skills/verification-before-completion \
      /home/daytona/.claude/skills/verification-before-completion \
      /home/daytona/.pi/mte-profile/skills/verification-before-completion; do \
      install -d -m 0755 "$destination/agents"; \
      install -m 0644 /opt/mte-skill/SKILL.md "$destination/SKILL.md"; \
      install -m 0644 /opt/mte-skill/agents/openai.yaml "$destination/agents/openai.yaml"; \
    done; \
    chown -R daytona:daytona /home/daytona/.agents /home/daytona/.claude /home/daytona/.pi; \
    chmod 0644 /etc/claude-code/managed-mcp.json; \
    git config --system user.name 'Paperclip Agent'; \
    git config --system user.email 'paperclip-agent@users.noreply.github.com'; \
    git config --system init.defaultBranch main; \
    git config --system credential.https://github.com.helper '!gh auth git-credential'; \
    codex --version; \
    claude --version; \
    pi --version; \
    thv version; \
    gh --version; \
    rg --version; \
    jq --version

USER daytona
WORKDIR /home/daytona/paperclip-workspace
