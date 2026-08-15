# Engineering Onboarding Notes (Internal)

Welcome to the team. This is an informal internal note, not a reviewed policy
document, so treat it as guidance rather than authority.

## First week
Get access to the code repository, the ticketing system, and the staging
environment. Your manager will assign a buddy who can answer day-to-day
questions.

## Development environment
We use Python 3.11+, a virtual environment per project, and pinned dependency
lock files. Never install packages ad hoc into a shared environment. Run the
test suite before opening a pull request.

## Deployment
Changes go through code review, then CI, then a staging deploy, then production.
The CI pipeline includes security scans; a red pipeline blocks the merge.

## Getting help
Ask early. It is normal to spend the first few weeks reading code and asking
questions. Nobody expects you to ship a large change in week one.
