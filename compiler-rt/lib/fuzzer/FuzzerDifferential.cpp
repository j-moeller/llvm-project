#include "FuzzerDifferential.h"

#include "FuzzerIO.h"
#include "FuzzerSHA1.h"

#include <iostream>

namespace fuzzer {
DTManager DTM;
extern TracePC TPC;
} // namespace fuzzer

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

static int n_modules = 0;
static int n_pctables = 0;

extern "C" {
void LLVMFuzzerStartRegistration() {
  n_modules = fuzzer::DTM.getNumberOfModules();
  n_pctables = fuzzer::DTM.getNumberOfPCTables();
}
void LLVMFuzzerEndRegistration() {
  fuzzer::DTM.registerProgramCoverage(
      {n_modules, fuzzer::DTM.getNumberOfModules()},
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
int DTManager::getNumberOfModules() const { return TPC.NumModules; }

int DTManager::getNumberOfPCTables() const { return TPC.NumPCTables; }

void DTManager::registerProgramCoverage(Range modules, Range pctables) {
  this->targets.push_back({modules, pctables});
}

void DTManager::startBatch(const uint8_t *Data, size_t Size) {
  this->inputData = {Data, Data + Size};

  this->batchResult.ExitCode = std::vector<int>(this->targets.size());
  this->batchResult.Output =
      std::vector<std::vector<uint8_t>>(this->targets.size());
  this->batchResult.PDCoarse = std::vector<int>(this->targets.size());
  this->batchResult.PCFine = std::vector<int>(this->targets.size());
  this->interestingState = false;
}

void DTManager::endBatch() {
  bool allParsersReject = std::all_of(
      this->batchResult.ExitCode.begin(), this->batchResult.ExitCode.end(),
      [](int exit_code) { return exit_code != 0; });

  if (allParsersReject) {
    return;
  }

  auto newExitCodeTuple = [&]() {
    uint32_t hash = hashVector(this->batchResult.ExitCode);
    return this->cumResult.ExitCodeHashes.insert(hash);
  }();

  auto newCoarseTuple = [&]() {
    uint32_t hash = hashVector(this->batchResult.PDCoarse);
    return this->cumResult.PDCoarseHashes.insert(hash);
  }();

  auto newFineTuple = [&]() {
    uint32_t hash = hashVector(this->batchResult.PCFine);
    return this->cumResult.PCFineHashes.insert(hash);
  }();

  this->interestingState |= newExitCodeTuple.second;
  this->interestingState |= newCoarseTuple.second;
  this->interestingState |= newFineTuple.second;

  auto normalizeJSON = [](const Unit &u) {
    Unit s = {u.begin(), u.end()};
    s.erase(std::remove(s.begin(), s.end(), 0x20), s.end());
    s.erase(std::remove(s.begin(), s.end(), 0x0a), s.end());
    s.erase(std::remove(s.begin(), s.end(), 0x0d), s.end());
    s.erase(std::remove(s.begin(), s.end(), 0x09), s.end());
    return s;
  };

  // auto normalizedInput = normalizeJSON(this->inputData);

  std::set<std::string> outputs;
  for (int i = 0; i < this->batchResult.Output.size(); i++) {
    auto &output = this->batchResult.Output[i];
    auto normalized = normalizeJSON(output);
    outputs.insert(std::string(normalized.begin(), normalized.end()));
  }

  if (outputs.size() < int(0.25 * this->targets.size())) {
    return;
  }

  // TODO: <discarded> => -1
  // TODO: frequency of parser exit code == 0 vs == 1
  // TODO: Some parser parse until first error and then return. (configuration?)
  // TODO: Count frequency of terminal symbols
  // TODO: Die selbe Zahl kann auf verschiedene Weise dargestellt werden (1.0e0,
  // 1e0, 1e+0)
  // TODO: Wo hört die Fuzzing-Harness auf und wo beginnt unsere

  // TODO: Parser rausschmeißen, die bekannte Fehler schon haben. Können wir
  // trotzdem die Baseline reproduzieren?

  // TODO:
  // diff-4-1154645317-1478706547-3590309516-523acd6dae2d6a81b8553d6df37c9cc710ba4677
  // 4294967295

  // TODO: Felix' afl-tmin implementieren.

  // TODO: Manche sind 0-terminiert andere nicht.

  auto newTuple = [&]() {
    int hash = 0;
    hash = hashInt(*newExitCodeTuple.first, hash);
    hash = hashInt(*newCoarseTuple.first, hash);
    hash = hashInt(*newFineTuple.first, hash);
    return this->cumResult.TupleHashes.insert(hash);
  }();

  if (*newCoarseTuple.first && *newFineTuple.first) {
    std::stringstream ss;
    ss << "output/diffs/diff-" << outputs.size() << "-"
       << *newExitCodeTuple.first << "-" << *newCoarseTuple.first << "-"
       << *newFineTuple.first << "-" << fuzzer::Hash(this->inputData);
    std::string filename = ss.str();
    fuzzer::WriteToFile(this->inputData, filename);
  }
}

void DTManager::startRun(int targetIndex) {}

void DTManager::endRun(int targetIndex, int exit_code,
                       const uint8_t *OutputData, size_t OutputSize) {
  auto &target = this->targets[targetIndex];
  auto &modules = target.modules;

  this->batchResult.ExitCode[targetIndex] = exit_code;
  this->batchResult.Output[targetIndex] =
      std::vector<uint8_t>(OutputData, OutputData + OutputSize);

  int edgeHash = 0;

  for (int moduleIndex = modules.start; moduleIndex < modules.end;
       moduleIndex++) {
    auto &m = TPC.Modules[moduleIndex];

    for (uint8_t *edge = m.Start(); edge < m.Stop(); edge++) {
      if (*edge) {
        this->batchResult.PDCoarse[targetIndex] += *edge;
        edgeHash = hashInt(reinterpret_cast<std::uintptr_t>(edge), edgeHash);
      }
    }
  }

  this->batchResult.PCFine[targetIndex] = edgeHash;
}

bool DTManager::isInterestingRun() const { return this->interestingState; }
} // namespace fuzzer