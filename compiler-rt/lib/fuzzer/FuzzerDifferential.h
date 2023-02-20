#ifndef FUZZER_DIFFERENTIAL_H
#define FUZZER_DIFFERENTIAL_H

#include <set>
#include <vector>

#include "FuzzerTracePC.h"

// #define ANALYSE_COVERAGE_MISMATCH
#define CHECK_FOR_COVERAGE_MISMATCH

#ifdef ANALYSE_COVERAGE_MISMATCH
#define CHECK_FOR_COVERAGE_MISMATCH
static const int DEBUG_INDEX = 0;
#endif

#ifdef CHECK_FOR_COVERAGE_MISMATCH
static const bool DEBUG_COVERAGE_MISMATCH = false;
#endif

namespace fuzzer {

struct Range {
  int start;
  int end;
};

struct Target {
  std::string identifier;
  Range modules;
  Range pctables;
};

struct BatchResult {
  /**
   * Output (i.e. serialized internal representation) for each target
   */
  std::vector<Unit> Output;

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

  std::vector<uintptr_t> DEBUG_edges;
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
  void registerProgramCoverage(std::string id, Range modules, Range pctables);

  void startBatch(const uint8_t *, size_t);
  void endBatch();
  void startRun(int);
  void endRun(int, int, const uint8_t *, size_t);

  bool isInterestingRun() const;

  std::vector<Target> targets;

  BatchResult batchResult;
  CumulativeResults cumResult;

  Unit inputData;
  bool interestingState = false;
};

uint32_t hashInt(uint32_t x, uint32_t seed);
uint32_t hashVector(const std::vector<int> &vec);
uint32_t hashVector(const fuzzer::Unit &vec);

}; // namespace fuzzer

#endif