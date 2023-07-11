#ifndef FUZZER_DIFFERENTIAL_H
#define FUZZER_DIFFERENTIAL_H

#include <set>
#include <vector>

#include "FuzzerTracePC.h"

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

struct EdgeCoverage {
  uintptr_t PC;
  uintptr_t ptr;
  uint8_t hits;
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

  Unit inputData;
  std::vector<std::vector<EdgeCoverage>> edges;
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

  bool interestingState = false;
};

uint32_t hashInt(uint32_t x, uint32_t seed);
uint32_t hashVector(const std::vector<int> &vec);
uint32_t hashVector(const Unit &vec);

}; // namespace fuzzer

#endif