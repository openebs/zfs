---
name: Bug report
about: Tell us about a problem you are experiencing
labels: Bug

---

**What steps did you take and what happened:**
[A clear and concise description of what the bug is, and what commands you ran.]


**What did you expect to happen:**


**The output of the following commands and cstor pod logs will help us better understand what's going on**:
(Pasting long output into a [GitHub gist](https://gist.github.com) or other [Pastebin](https://pastebin.com/) is fine.)

* `kubectl logs deployment/maya-apiserver -n openebs`
* `kubectl logs deployment/<pv-name>-target -n <openebs_namespace> -c cstor-istgt`
* `kubectl get pods -n openebs`
* `kubectl get cvr,spc,csp,cstorvolume -A -o yaml`

**Anything else you would like to add:**
[Miscellaneous information that will assist in solving the issue.]


**Environment:**
- OpenEBS version
- Kubernetes version (use `kubectl version`):
- Kubernetes installer & version:
- Cloud provider or hardware configuration:
- OS (e.g. from `/etc/os-release`):
