#include "FuzzerDifferential.h"

#include "FuzzerIO.h"
#include "FuzzerSHA1.h"
#include "FuzzerUtil.h"

#include <cmath>
#include <fstream>
#include <iostream>
#include <map>
#include <numeric>
#include <regex>

namespace fuzzer {

DTManager DTM;
extern TracePC TPC;

uint32_t hashInt(uint32_t x, uint32_t seed) {
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = (x >> 16) ^ x;
  seed ^= x + 0x9e3779b9 + (seed << 6) + (seed >> 2);

  return seed;
}

uint32_t hashVector(const std::vector<int> &vec) {
  uint32_t seed = vec.size();
  for (auto x : vec) {
    seed = hashInt(x, seed);
  }
  return seed;
}

uint32_t hashVector(const Unit &vec) {
  uint32_t seed = vec.size();
  for (auto x : vec) {
    seed = hashInt(x, seed);
  }
  return seed;
}

} // namespace fuzzer

// TODO: Make sure that LLVMFuzzerStartRegistration and
// LLVMFuzzerEndRegistration are called with the same identifier
static int n_modules = 0;
static int n_pctables = 0;

extern "C" {
void LLVMFuzzerStartRegistration(const char *) {
  n_modules = fuzzer::DTM.getNumberOfModules();
  n_pctables = fuzzer::DTM.getNumberOfPCTables();
}
void LLVMFuzzerEndRegistration(const char *id) {
  fuzzer::DTM.registerProgramCoverage(
      id, {n_modules, fuzzer::DTM.getNumberOfModules()},
      {n_pctables, fuzzer::DTM.getNumberOfPCTables()});
}
void LLVMFuzzerStartBatch(const uint8_t *Data, size_t Size) {
  fuzzer::DTM.startBatch(Data, Size);
}
void LLVMFuzzerEndBatch() { fuzzer::DTM.endBatch(); }
void LLVMFuzzerStartRun(int i) { fuzzer::DTM.startRun(i); }
void LLVMFuzzerEndRun(int i, int exit_code, const uint8_t *data, size_t size) {
  fuzzer::DTM.endRun(i, exit_code, data, size);
}
}

namespace fuzzer {

bool atLeastOneParserAccepts(const BatchResult &br) {
  auto sum = [](const int &acc, const int &v) {
    return (v == 0) ? acc + 1 : acc;
  };
  int n_success_exits =
      std::accumulate(br.ExitCode.begin(), br.ExitCode.end(), 0, sum);

  return n_success_exits > 0;
}

int DTManager::getNumberOfModules() const { return TPC.NumModules; }

int DTManager::getNumberOfPCTables() const { return TPC.NumPCTables; }

void DTManager::registerProgramCoverage(std::string id, Range modules,
                                        Range pctables) {
  int size = 0;
  for (int i = modules.start; i < modules.end; i++) {
    size += TPC.Modules[i].Size();
  }

  int n_pctables = 0;
  for (int i = pctables.start; i < pctables.end; i++) {
    n_pctables += TPC.ModulePCTable[i].Stop - TPC.ModulePCTable[i].Start;
  }

  assert(size == n_pctables);

  std::cerr << "Registered '" << std::string(id) << "' with "
            << std::to_string(size) << " edges" << std::endl;

  this->targets.push_back({id, modules, pctables});
}

void DTManager::startBatch(const uint8_t *Data, size_t Size) {
  this->batchResult.inputData = {Data, Data + Size};

  this->batchResult.ExitCode = std::vector<int>(this->targets.size());
  this->batchResult.Output = std::vector<Unit>(this->targets.size());
  this->batchResult.PDCoarse = std::vector<int>(this->targets.size());
  this->batchResult.PCFine = std::vector<int>(this->targets.size());
  this->batchResult.edges =
      std::vector<std::vector<EdgeCoverage>>(this->targets.size());
  this->interestingState = false;
}

void DTManager::endBatch() {
  if (!atLeastOneParserAccepts(this->batchResult)) {
    return;
  }

  auto hashAndInsert = [&](const std::vector<int> &vec,
                           std::set<uint32_t> &set) {
    uint32_t hash = hashVector(vec);
    return set.insert(hash);
  };

  auto exitCodesIter =
      hashAndInsert(this->batchResult.ExitCode, this->cumResult.ExitCodeHashes);

  auto coarseTupleIter =
      hashAndInsert(this->batchResult.PDCoarse, this->cumResult.PDCoarseHashes);

  auto fineTupleIter =
      hashAndInsert(this->batchResult.PCFine, this->cumResult.PCFineHashes);

  this->interestingState &= exitCodesIter.second;
  this->interestingState &= coarseTupleIter.second;
  this->interestingState &= fineTupleIter.second;
}

void DTManager::startRun(int targetIndex) {}

void DTManager::endRun(int targetIndex, int exit_code,
                       const uint8_t *OutputData, size_t OutputSize) {
  auto &target = this->targets[targetIndex];
  auto &modules = target.modules;
  auto &pctables = target.pctables;

  assert(modules.end - modules.start == pctables.end - pctables.start);
  const int n_modules = modules.end - modules.start;

  /*
   * Exit code
   */
  this->batchResult.ExitCode[targetIndex] = exit_code;

  /*
   * (string) Output
   */
  this->batchResult.Output[targetIndex] =
      Unit(OutputData, OutputData + OutputSize);

  /*
   * Edges
   * PDCoarse
   * PCFine
   */
  int edgeHash = 0;

  for (int i = 0; i < n_modules; i++) {
    auto moduleIndex = modules.start + i;
    auto pctableIndex = pctables.start + i;

    auto &module = TPC.Modules[moduleIndex];
    auto &pctable = TPC.ModulePCTable[pctableIndex];

    const int n_edges = module.Size();
    assert(n_edges == pctable.Stop - pctable.Start);

    for (size_t r = 0; r < module.NumRegions; r++) {
      auto &region = module.Regions[r];
      if (!region.Enabled) {
        continue;
      }
      for (uint8_t *edge = region.Start; edge < region.Stop; edge++) {
        if (*edge) {
          int edgeIdx = module.Idx(edge);
          auto *entry = &pctable.Start[edgeIdx];

          this->batchResult.edges[targetIndex].push_back(
              {reinterpret_cast<std::uintptr_t>(entry->PC),
               reinterpret_cast<std::uintptr_t>(edge), *edge});

          this->batchResult.PDCoarse[targetIndex] += *edge;
          edgeHash = hashInt(reinterpret_cast<std::uintptr_t>(edge), edgeHash);
        }
      }
    }
  }

  this->batchResult.PCFine[targetIndex] = edgeHash;
}

bool DTManager::isInterestingRun() const { return this->interestingState; }
} // namespace fuzzer