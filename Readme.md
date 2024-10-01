# RISKEN Azure

![Build Status](https://codebuild.ap-northeast-1.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoidnhLNmNsbVhkVGlaNDArVGIvT3RwZ29IdGFhSlZleUJyNzUwM00yRVhwSG9wR0tWd21WSG1NZ21yc0FCRTM3QjlYWkxUeWtMdTFURGdMN3lQekVJanRFPSIsIml2UGFyYW1ldGVyU3BlYyI6Im9SSTRtMVE4WkdlVHpDNkMiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=main)

`RISKEN` is a monitoring tool for your cloud platforms, web-site, source-code... 
`RISKEN Azure` is a security monitoring system for Azure that searches, analyzes, evaluate, and alerts on discovered threat information.

Please check [RISKEN Documentation](https://docs.security-hub.jp/).

## Installation

### Requirements

This module requires the following modules:

- [Go](https://go.dev/doc/install)
- [Docker](https://docs.docker.com/get-docker/)

### Building

Build the containers on your machine with the following command

```bash
$ make build
```

### Running Apps

Deploy the pre-built containers to the Kubernetes environment on your local machine.

- Follow the [documentation](https://docs.security-hub.jp/admin/infra_local/#risken) to download the Kubernetes manifest sample.
- Fix the Kubernetes object specs of the manifest file as follows and deploy it.

`k8s-sample/overlays/local/azure.yaml`

| service        | spec                                | before (public images)                            | after (pre-build images on your machine) |
| -------------- | ----------------------------------- | ------------------------------------------------- | ---------------------------------------- |
| prowler | spec.template.spec.containers.image | `public.ecr.aws/risken/azure/prowler:latest` | `azure/prowler:latest`              |

## Community

Info on reporting bugs, getting help, finding roadmaps,
and more can be found in the [RISKEN Community](https://github.com/ca-risken/community).

## License

[MIT](LICENSE).
