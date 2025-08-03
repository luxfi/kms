<h1 align="center">
  <img width="300" src="/img/logoname-white.svg#gh-dark-mode-only" alt="kms">
</h1>
<p align="center">
  <p align="center"><b>The open-source secret management platform</b>: Sync secrets/configs across your team/infrastructure and prevent secret leaks.</p>
</p>

<h4 align="center">
  <a href="https://lux.network/slack">Slack</a> |
  <a href="https://lux.network/">KMS Cloud</a> |
  <a href="https://lux.network/docs/self-hosting/overview">Self-Hosting</a> |
  <a href="https://lux.network/docs/documentation/getting-started/introduction">Docs</a> |
  <a href="https://www.lux.network">Website</a> |
  <a href="https://lux.network/careers">Hiring (Remote/SF)</a>
</h4>

<h4 align="center">
  <a href="https://github.com/luxfi/kms/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="KMS is released under the MIT license." />
  </a>
  <a href="https://github.com/kms/kms/blob/main/CONTRIBUTING.md">
    <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen" alt="PRs welcome!" />
  </a>
  <a href="https://github.com/luxfi/kms/issues">
    <img src="https://img.shields.io/github/commit-activity/m/kms/kms" alt="git commit activity" />
  </a>
  <a href="https://cloudsmith.io/~kms/repos/">
    <img src="https://img.shields.io/badge/Downloads-6.95M-orange" alt="Cloudsmith downloads" />
  </a>
  <a href="https://lux.network/slack">
    <img src="https://img.shields.io/badge/chat-on%20Slack-blueviolet" alt="Slack community channel" />
  </a>
  <a href="https://twitter.com/kms">
    <img src="https://img.shields.io/twitter/follow/kms?label=Follow" alt="KMS Twitter" />
  </a>
</h4>

<img src="/img/kms_github_repo2.png" width="100%" alt="Dashboard" />

## Introduction

**[KMS](https://lux.network)** is the open source secret management platform that teams use to centralize their application configuration and secrets like API keys and database credentials as well as manage their internal PKI.

We're on a mission to make security tooling more accessible to everyone, not just security teams, and that means redesigning the entire developer experience from ground up.

## Features

### Secrets Management:

- **[Dashboard](https://lux.network/docs/documentation/platform/project)**: Manage secrets across projects and environments (e.g. development, production, etc.) through a user-friendly interface.
- **[Native Integrations](https://lux.network/docs/integrations/overview)**: Sync secrets to platforms like [GitHub](https://lux.network/docs/integrations/cicd/githubactions), [Vercel](https://lux.network/docs/integrations/cloud/vercel), [AWS](https://lux.network/docs/integrations/cloud/aws-secret-manager), and use tools like [Terraform](https://lux.network/docs/integrations/frameworks/terraform), [Ansible](https://lux.network/docs/integrations/platforms/ansible), and more.
- **[Secret versioning](https://lux.network/docs/documentation/platform/secret-versioning)** and **[Point-in-Time Recovery](https://lux.network/docs/documentation/platform/pit-recovery)**: Keep track of every secret and project state; roll back when needed.
- **[Secret Rotation](https://lux.network/docs/documentation/platform/secret-rotation/overview)**: Rotate secrets at regular intervals for services like [PostgreSQL](https://lux.network/docs/documentation/platform/secret-rotation/postgres-credentials), [MySQL](https://lux.network/docs/documentation/platform/secret-rotation/mysql), [AWS IAM](https://lux.network/docs/documentation/platform/secret-rotation/aws-iam), and more.
- **[Dynamic Secrets](https://lux.network/docs/documentation/platform/dynamic-secrets/overview)**: Generate ephemeral secrets on-demand for services like [PostgreSQL](https://lux.network/docs/documentation/platform/dynamic-secrets/postgresql), [MySQL](https://lux.network/docs/documentation/platform/dynamic-secrets/mysql), [RabbitMQ](https://lux.network/docs/documentation/platform/dynamic-secrets/rabbit-mq), and more.
- **[Secret Scanning and Leak Prevention](https://lux.network/docs/cli/scanning-overview)**: Prevent secrets from leaking to git.
- **[KMS Kubernetes Operator](https://lux.network/docs/documentation/getting-started/kubernetes)**: Deliver secrets to your Kubernetes workloads and automatically reload deployments.
- **[KMS Agent](https://lux.network/docs/kms-agent/overview)**: Inject secrets into applications without modifying any code logic.

### KMS (Internal) PKI:

- **[Private Certificate Authority](https://lux.network/docs/documentation/platform/pki/private-ca)**: Create CA hierarchies, configure [certificate templates](https://lux.network/docs/documentation/platform/pki/certificates#guide-to-issuing-certificates) for policy enforcement, and start issuing X.509 certificates.
- **[Certificate Management](https://lux.network/docs/documentation/platform/pki/certificates)**: Manage the certificate lifecycle from [issuance](https://lux.network/docs/documentation/platform/pki/certificates#guide-to-issuing-certificates) to [revocation](https://lux.network/docs/documentation/platform/pki/certificates#guide-to-revoking-certificates) with support for CRL.
- **[Alerting](https://lux.network/docs/documentation/platform/pki/alerting)**: Configure alerting for expiring CA and end-entity certificates.
- **[KMS PKI Issuer for Kubernetes](https://lux.network/docs/documentation/platform/pki/pki-issuer)**: Deliver TLS certificates to your Kubernetes workloads with automatic renewal.
- **[Enrollment over Secure Transport](https://lux.network/docs/documentation/platform/pki/est)**: Enroll and manage certificates via EST protocol.

### KMS Key Management System (KMS):

- **[Cryptographic Keys](https://lux.network/docs/documentation/platform/kms)**: Centrally manage keys across projects through a user-friendly interface or via the API.
- **[Encrypt and Decrypt Data](https://lux.network/docs/documentation/platform/kms#guide-to-encrypting-data)**: Use symmetric keys to encrypt and decrypt data.

### KMS SSH

- **[Signed SSH Certificates](https://lux.network/docs/documentation/platform/ssh)**: Issue ephemeral SSH credentials for secure, short-lived, and centralized access to infrastructure.

### General Platform:

- **Authentication Methods**: Authenticate machine identities with KMS using a cloud-native or platform agnostic authentication method ([Kubernetes Auth](https://lux.network/docs/documentation/platform/identities/kubernetes-auth), [GCP Auth](https://lux.network/docs/documentation/platform/identities/gcp-auth), [Azure Auth](https://lux.network/docs/documentation/platform/identities/azure-auth), [AWS Auth](https://lux.network/docs/documentation/platform/identities/aws-auth), [OIDC Auth](https://lux.network/docs/documentation/platform/identities/oidc-auth/general), [Universal Auth](https://lux.network/docs/documentation/platform/identities/universal-auth)).
- **[Access Controls](https://lux.network/docs/documentation/platform/access-controls/overview)**: Define advanced authorization controls for users and machine identities with [RBAC](https://lux.network/docs/documentation/platform/access-controls/role-based-access-controls), [additional privileges](https://lux.network/docs/documentation/platform/access-controls/additional-privileges), [temporary access](https://lux.network/docs/documentation/platform/access-controls/temporary-access), [access requests](https://lux.network/docs/documentation/platform/access-controls/access-requests), [approval workflows](https://lux.network/docs/documentation/platform/pr-workflows), and more.
- **[Audit logs](https://lux.network/docs/documentation/platform/audit-logs)**: Track every action taken on the platform.
- **[Self-hosting](https://lux.network/docs/self-hosting/overview)**: Deploy KMS on-prem or cloud with ease; keep data on your own infrastructure.
- **[KMS SDK](https://lux.network/docs/sdks/overview)**: Interact with KMS via client SDKs ([Node](https://lux.network/docs/sdks/languages/node), [Python](https://github.com/KMS/python-sdk-official?tab=readme-ov-file#kms-python-sdk), [Go](https://lux.network/docs/sdks/languages/go), [Ruby](https://lux.network/docs/sdks/languages/ruby), [Java](https://lux.network/docs/sdks/languages/java), [.NET](https://lux.network/docs/sdks/languages/csharp))
- **[KMS CLI](https://lux.network/docs/cli/overview)**: Interact with KMS via CLI; useful for injecting secrets into local development and CI/CD pipelines.
- **[KMS API](https://lux.network/docs/api-reference/overview/introduction)**: Interact with KMS via API.

## Getting started

Check out the [Quickstart Guides](https://lux.network/docs/getting-started/introduction)

| Use KMS Cloud                                                                                                                                     | Deploy KMS on premise                                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| The fastest and most reliable way to <br> get started with KMS is signing up <br> for free to [KMS Cloud](https://kms.lux.network/login). | <br> View all [deployment options](https://lux.network/docs/self-hosting/overview) |

### Run KMS locally

To set up and run KMS locally, make sure you have Git and Docker installed on your system. Then run the command for your system:

Linux/macOS:

```console
git clone https://github.com/luxfi/kms && cd "$(basename $_ .git)" && cp .env.example .env && docker compose -f docker-compose.prod.yml up
```

Windows Command Prompt:

```console
git clone https://github.com/luxfi/kms && cd kms && copy .env.example .env && docker compose -f docker-compose.prod.yml up
```

Create an account at `http://localhost:80`

### Scan and prevent secret leaks

On top managing secrets with KMS, you can also [scan for over 140+ secret types]() in your files, directories and git repositories.

To scan your full git history, run:

```
kms scan --verbose
```

Install pre commit hook to scan each commit before you push to your repository

```
kms scan install --pre-commit-hook
```

Learn about KMS's code scanning feature [here](https://lux.network/docs/cli/scanning-overview)

## Open-source vs. paid

This repo available under the [MIT expat license](https://github.com/luxfi/kms/blob/main/LICENSE), with the exception of the `ee` directory which will contain premium enterprise features requiring a KMS license.

If you are interested in managed KMS Cloud of self-hosted Enterprise Offering, take a look at [our website](https://lux.network/) or [book a meeting with us](https://kms.cal.com/vlad/kms-demo).

## Security

Please do not file GitHub issues or post on our public forum for security vulnerabilities, as they are public!

KMS takes security issues very seriously. If you have any concerns about KMS or believe you have uncovered a vulnerability, please get in touch via the e-mail address security@lux.network. In the message, try to provide a description of the issue and ideally a way of reproducing it. The security team will get back to you as soon as possible.

Note that this security address should be used only for undisclosed vulnerabilities. Please report any security problems to us before disclosing it publicly.

## Contributing

Whether it's big or small, we love contributions. Check out our guide to see how to [get started](https://lux.network/docs/contributing/getting-started).

Not sure where to get started? You can:

- Join our <a href="https://lux.network/slack">Slack</a>, and ask us any questions there.

## We are hiring!

If you're reading this, there is a strong chance you like the products we created.

You might also make a great addition to our team. We're growing fast and would love for you to [join us](https://lux.network/careers).
