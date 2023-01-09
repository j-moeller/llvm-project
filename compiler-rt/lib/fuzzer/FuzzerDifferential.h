#ifndef FUZZER_DIFFERENTIAL_H
#define FUZZER_DIFFERENTIAL_H

#include <set>
#include <vector>

#include "FuzzerTracePC.h"

struct Range {
  int start;
  int end;
};

struct Target {
  Range modules;
  Range pctables;
};

struct BatchResult {
  /**
   * Output (i.e. serialized internal representation) for each target
   */
  std::vector<std::vector<uint8_t>> Output;

  /**
   * Nezha implementation:
   *
   * https://www.cs.columbia.edu/~theofilos/files/papers/2017/nezha.pdf
   */

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
};

struct CumulativeResults {
  std::set<uint32_t> ExitCodeHashes;
  std::set<uint32_t> PDCoarseHashes;
  std::set<uint32_t> PCFineHashes;

  std::set<uint32_t> TupleHashes;
};

namespace fuzzer {

class DTManager {
public:
  int getNumberOfModules() const;
  int getNumberOfPCTables() const;
  void registerProgramCoverage(Range modules, Range pctables);

  void startBatch(const uint8_t *, size_t);
  void endBatch();
  void startRun(int);
  void endRun(int, int, const uint8_t *, size_t);

  bool isInterestingRun() const;

private:
  std::vector<Target> targets;

  BatchResult batchResult;
  CumulativeResults cumResult;

  Unit inputData;
  bool interestingState = false;
};

}; // namespace fuzzer

#endif