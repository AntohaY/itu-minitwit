# Final Report Checklist

Use this checklist to track the work required by `MSc_lecture_notes/REPORT.md` before the final hand-in.

## Administrative Registration

- [ ] Verify that all group member information is correct in the course group spreadsheet.
- [ ] Verify that this repository is correctly registered in `MSc_lecture_notes/repositories.py`.
- [ ] Verify that the production, monitoring, and logging URLs are correctly registered in `MSc_lecture_notes/misc_urls.py`.
- [ ] Add the final report URL to `MSc_lecture_notes/final_report_urls.py` through a pull request.

## Repository Polish

- [ ] Create or update the root `.mailmap`.
- [ ] Run `git shortlog -sne` and identify duplicate author identities.
- [ ] Map each real author to `Name <itu_id@itu.dk>`.
- [ ] Map any LLM co-authors to `LLM <none>`.
- [ ] Re-run `git shortlog -sne` and confirm the author list is clean.
- [ ] Update the root `README.md` with a correct project summary.
- [ ] Document how to run the system locally.
- [ ] Document how to deploy or operate the production system.
- [ ] Document how contributors get changes into production.

## Report Structure

- [ ] Create a root `report/` directory.
- [ ] Add the report source files to `report/`.
- [ ] Add all report images to `report/images/`.
- [ ] Reference images from Markdown using paths such as `images/architecture.png`.
- [ ] Create `report/build/` for the generated PDF.
- [ ] Ensure the PDF is named `MSc_group_[letter].pdf`, for example `MSc_group_x.pdf`.
- [ ] Keep the report at or below 2500 words.
- [ ] Link all constitutional artifacts from the report, including repositories, issue trackers, monitoring dashboards, and logging dashboards.

## PDF Build Through CI

- [ ] Add a GitHub Actions workflow that builds the report PDF.
- [ ] If the report is Markdown, use a tool such as Pandoc.
- [ ] If the report is LaTeX, use a LaTeX build action.
- [ ] Ensure CI writes the generated PDF to `report/build/`.
- [ ] Ensure the generated PDF is committed or otherwise available in the repository as required for hand-in.
- [ ] Run the workflow and verify the PDF is readable.

## Report Content: System Perspective

- [ ] Describe the design and architecture of the ITU-MiniTwit system.
- [ ] Include an architecture diagram.
- [ ] Describe application dependencies, infrastructure dependencies, and operational tooling.
- [ ] Summarize the current system state.
- [ ] Include relevant quality evidence, such as tests, linting, static analysis, or other assessments.
- [ ] Reuse or reference content from `docs/architecture.md`, `docs/database.md`, `docs/api.md`, `docs/testing.md`, and `docs/infrastructure.md`.

## Report Content: Process Perspective

- [ ] Describe the CI/CD pipeline stages and tools.
- [ ] Include a CI/CD or deployment diagram.
- [ ] Explain how deployment and release work.
- [ ] Explain what is monitored and why.
- [ ] Explain what is logged and how logs are aggregated.
- [ ] Describe security hardening.
- [ ] Describe availability and scaling decisions.
- [ ] Reuse or reference content from `docs/ci-cd.md`, `docs/deployment.md`, `docs/monitoring.md`, `docs/logging.md`, `docs/security.md`, and `docs/scaling-and-availability.md`.

## Report Content: Reflection Perspective

- [ ] Describe the biggest evolution and refactoring issues.
- [ ] Describe the biggest operational issues.
- [ ] Describe the biggest maintenance issues.
- [ ] Explain how the team solved those issues.
- [ ] Link to relevant commits, issues, pull requests, tickets, or decision records.
- [ ] Reflect on what was DevOps-like about the team workflow.
- [ ] Explain what worked differently compared with previous development projects.
- [ ] Reuse or reference content from `docs/project-history.md`, `docs/operations.md`, and `docs/decisions/`.

## Report Content: Generative AI

- [ ] State which generative AI tools were used.
- [ ] Describe which project tasks they were used for.
- [ ] Explain how the tools were used.
- [ ] Reflect on how they supported the work.
- [ ] Reflect on how they hindered or complicated the work.
- [ ] Ensure any AI co-authorship in commits is represented in `.mailmap` as `LLM <none>`.

## Final Hand-In

- [ ] Confirm the final PDF exists at `report/build/MSc_group_[letter].pdf`.
- [ ] Confirm the same PDF filename is used for WISEflow.
- [ ] Open the required pull request to `itu-devops/MSc_lecture_notes`.
- [ ] Submit the PDF on LearnIT/WISEflow before Monday, May 18, 2026 at 14:00.
