#include "FuzzerDifferentialInternal.h"

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

} // namespace fuzzer

static int number_of_modules = 0;
static int number_of_pctables = 0;

extern "C" {
void LLVMFuzzerStartRegistration() {
  number_of_modules = fuzzer::DTM.getNumberOfModules();
  number_of_pctables = fuzzer::DTM.getNumberOfPCTables();
}

int LLVMFuzzerEndRegistration() {
  return fuzzer::DTM.registerProgramCoverage(
      {number_of_modules, fuzzer::DTM.getNumberOfModules()},
      {number_of_pctables, fuzzer::DTM.getNumberOfPCTables()});
}

void LLVMFuzzerGetSectionInfo(int handler, FDSection *info) {
  auto &section = fuzzer::DTM.sections[handler];

  info->modules.start = section.modules.start;
  info->modules.end = section.modules.end;
  info->pctables.start = section.pctables.start;
  info->pctables.end = section.pctables.end;
}

void LLVMFuzzerStartBatch(int n_targets) { fuzzer::DTM.startBatch(n_targets); }
void LLVMFuzzerEndBatch() { fuzzer::DTM.endBatch(); }

int LLVMFuzzerStartRun() { return fuzzer::DTM.startRun(); }
void LLVMFuzzerEndRun(const int *sectionIds, int sectionsSize, int exitCode) {
  fuzzer::DTM.endRun(sectionIds, sectionsSize, exitCode);
}

void LLVMTargetCoverage(int targetIndex, const unsigned long **edges,
                        int *edgeSize) {
  fuzzer::DTM.getTargetCoverage(targetIndex, edges, edgeSize);
}

void LLVMNezhaCoverage(int *coarseCoverage, int *fineCoverage) {
  fuzzer::DTM.getNezhaCoverage(coarseCoverage, fineCoverage);
}
}

namespace fuzzer {

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

int DTManager::registerProgramCoverage(FDRange modules, FDRange pctables) {
  int size = 0;
  for (int i = modules.start; i < modules.end; i++) {
    size += TPC.Modules[i].Size();
  }

  int n_pctables = 0;
  for (int i = pctables.start; i < pctables.end; i++) {
    n_pctables += TPC.ModulePCTable[i].Stop - TPC.ModulePCTable[i].Start;
  }

  assert(size == n_pctables);

  this->sections.push_back({modules, pctables});
  return this->sections.size() - 1;
}

void DTManager::startBatch(int n_targets) {
  this->batchResult.Edges = std::vector<std::vector<uintptr_t>>(n_targets);
  this->batchResult.ExitCode = std::vector<int>(n_targets);
  this->batchResult.PDCoarse = std::vector<int>(n_targets);
  this->batchResult.PCFine = std::vector<int>(n_targets);
  this->interestingState = false;
  this->currentTarget = 0;
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

int DTManager::startRun() { return this->currentTarget; }

void DTManager::endRun(const int *sectionIds, size_t sectionIdsSize,
                       int exitCode) {
  int edgeHash = 0;

  for (int xyz = 0; xyz < sectionIdsSize; xyz++) {
    int sectionId = sectionIds[xyz];

    auto &section = this->sections[sectionId];
    auto &modules = section.modules;
    auto &pctables = section.pctables;

    assert(modules.end - modules.start == pctables.end - pctables.start);
    const int n_modules = modules.end - modules.start;

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
            auto e = reinterpret_cast<std::uintptr_t>(edge);

            this->batchResult.Edges[this->currentTarget].push_back(e);
            this->batchResult.PDCoarse[this->currentTarget] += 1;
            edgeHash = hashInt(e, edgeHash);
          }
        }
      }
    }
  }

  this->batchResult.ExitCode[this->currentTarget] = exitCode;
  this->batchResult.PCFine[this->currentTarget] = edgeHash;

  this->currentTarget++;
}

void DTManager::getTargetCoverage(int targetIndex, const unsigned long **edges,
                                  int *edgeSize) const {
  const auto &edgeList = this->batchResult.Edges[targetIndex];

  *edges = &edgeList[0];
  *edgeSize = edgeList.size();
}

void DTManager::getNezhaCoverage(int *coarseCoverage, int *fineCoverage) const {
  *coarseCoverage = this->cumResult.PDCoarseHashes.size();
  *fineCoverage = this->cumResult.PCFineHashes.size();
}

bool DTManager::isInterestingRun() const { return this->interestingState; }
} // namespace fuzzer