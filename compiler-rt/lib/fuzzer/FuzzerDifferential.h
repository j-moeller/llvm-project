#ifndef FUZZER_DIFFERENTIAL_H
#define FUZZER_DIFFERENTIAL_H

struct FDRange {
  int start;
  int end;
};

/**
 * One fuzzing target may register multiple Sections of coverage (e.g.
 * dynamically at runtime).
 */
struct FDSection {
  FDRange modules;
  FDRange pctables;
};

void LLVMFuzzerStartRegistration();
int LLVMFuzzerEndRegistration();

void LLVMFuzzerGetSectionInfo(int handler, FDSection *info);

void LLVMFuzzerStartBatch(int n_targets);
void LLVMFuzzerEndBatch();

int LLVMFuzzerStartRun();
void LLVMFuzzerEndRun(const int *sectionIds, int sectionsSize, int exitCode);

void LLVMTargetCoverage(int targetIndex, const unsigned long **edges,
                        int *edgeSize);
void LLVMNezhaCoverage(int *coarseCoverage, int *fineCoverage);

#endif