# <repo name>

[![reuse compliant](https://reuse.software/badge/reuse-compliant.svg)](https://reuse.software/)

## How to use this repository template

This template repository can be used to seed new git repositories in the gardener github organisation.

- you need to be a [member of the gardener organisation](https://github.com/orgs/gardener/people)
  in order to be able to create a new private repository
- [create the new repository](https://docs.github.com/en/free-pro-team@latest/github/creating-cloning-and-archiving-repositories/creating-a-repository-from-a-template)
  based on this template repository
- in the files
  - `.reuse/dep5`
  - `CODEOWNERS`
  - `README.md`
- replace the following placeholders
  - `<repo name>`: name of the new repository
  - `<maintainer team>`: name of the github team in [gardener teams](https://github.com/orgs/gardener/teams)
    defining maintainers of the new repository.
    If several repositories share a common topic and the same
    set of maintainers they can share a common maintainer team
- set the repository description in the "About" section of your repository
- describe the new component in additional sections in this `README.md`
- any contributions to the new repository must follow the rules in the 
  [contributor guide](https://github.com/gardener/documentation/blob/master/CONTRIBUTING.md)
- remove this section from this `README.md`
- ask [@msohn](https://github.com/orgs/gardener/people/msohn) or another
  [owner of the gardener github organisation](https://github.com/orgs/gardener/people?query=role%3Aowner)
  - to double-check the initial content of this repository
  - to create the maintainer team for this new repository
  - to make this repository public
  - protect at least the master branch requiring mandatory code review by the maintainers defined in CODEOWNERS
  - grant admin permission to the maintainers team of the new repository defined in CODEOWNERS

## UNDER CONSTRUCTION
