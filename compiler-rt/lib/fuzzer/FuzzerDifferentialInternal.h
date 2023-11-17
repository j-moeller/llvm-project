#ifndef FUZZER_DIFFERENTIAL_INTERNAL_H
#define FUZZER_DIFFERENTIAL_INTERNAL_H

#include <set>
#include <vector>

extern "C" {
#include "FuzzerDifferential.h"
}
#include "FuzzerTracePC.h"

namespace fuzzer {

struct BatchResult {
  /**
   * Nezha implementation:
   *
   * https://www.cs.columbia.edu/~theofilos/files/papers/2017/nezha.pdf
   */

  std::vector<std::vector<uintptr_t>> Edges;

  /**
   * Exit code for each target
   */
  std::vector<int> ExitCode;

  /**
   * Number of edges visited by each target
   */
  std::vector<int> PDCoarse;

  /**
   * Set of edges visited by each target (only the hash of the set is saved)
   */
  std::vector<int> PCFine;

  Unit inputData;
};

struct CumulativeResults {
  std::set<uint32_t> ExitCodeHashes;
  std::set<uint32_t> PDCoarseHashes;
  std::set<uint32_t> PCFineHashes;

  std::set<uint32_t> TupleHashes;
};

class DTManager {
public:
  int getNumberOfModules() const;
  int getNumberOfPCTables() const;

  int registerProgramCoverage(FDRange modules, FDRange pctables);

  void startBatch(int n_targets);
  void endBatch();
  int startRun();
  void endRun(const int *, size_t, int);

  void getTargetCoverage(int targetIndex, const unsigned long **edges,
                         int *edgeSize) const;
  void getNezhaCoverage(int *coarseCoverage, int *fineCoverage) const;
  bool isInterestingRun() const;

  std::vector<FDSection> sections;

  BatchResult batchResult;
  CumulativeResults cumResult;

  bool interestingState = false;
  int currentTarget = 0;
};

uint32_t hashInt(uint32_t x, uint32_t seed);
uint32_t hashVector(const std::vector<int> &vec);
uint32_t hashVector(const Unit &vec);

}; // namespace fuzzer

#endif