/* Copyright 2017 - 2024 R. Thomas
 * Copyright 2017 - 2024 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef LIEF_PE_RICH_HEADER_H
#define LIEF_PE_RICH_HEADER_H
#include <ostream>

#include "LIEF/Object.hpp"
#include "LIEF/visibility.h"

#include "LIEF/iterators.hpp"

#include "LIEF/PE/RichEntry.hpp"
#include "LIEF/PE/enums.hpp"

namespace LIEF {
namespace PE {

//! Class which represents the not-so-documented rich header
//!
//! This structure is usually located at the end of the Binary::dos_stub
//! and contains information about the build environment.
//! It is generated by the Microsoft linker `link.exe` and there are no options to disable
//! or remove this information.
class LIEF_API RichHeader : public Object {
  public:

  using entries_t        = std::vector<RichEntry>;
  using it_entries       = ref_iterator<entries_t&>;
  using it_const_entries = const_ref_iterator<const entries_t&>;

  RichHeader() = default;
  RichHeader(const RichHeader&) = default;
  RichHeader& operator=(const RichHeader&) = default;
  ~RichHeader() override = default;

  //! Key used to encode the header (xor operation)
  uint32_t key() const {
    return key_;
  }

  //! Return an iterator over the PE::RichEntry within the header
  it_entries entries() {
    return entries_;
  }

  it_const_entries entries() const {
    return entries_;
  }

  void key(uint32_t key) {
    key_ = key;
  }

  //! Add a new PE::RichEntry
  void add_entry(RichEntry entry) {
    entries_.push_back(std::move(entry));
  }

  //! Add a new entry given the id, build_id and count
  void add_entry(uint16_t id, uint16_t build_id, uint32_t count) {
    entries_.emplace_back(id, build_id, count);
  }

  //! The raw structure of the Rich header without xor-encoding.
  //!
  //! This function is equivalent as calling RichHeader::raw(uint32_t) with a `xor_key` set to 0
  std::vector<uint8_t> raw() const {
    return raw(/*xor_key=*/0);
  }

  //! Given this rich header, this function re-computes
  //! the raw bytes of the structure with the provided xor-key.
  //!
  //! You can access the decoded data's structure with the @p xor_key set to 0
  //!
  //! @param[in] xor_key   The key to use for the xor-encoding (can be 0)
  std::vector<uint8_t> raw(uint32_t xor_key) const;

  //! Compute the hash of the decoded rich header structure with
  //! the given hash algorithm
  std::vector<uint8_t> hash(ALGORITHMS algo) const {
    return hash(algo, /*xor_key=*/0);
  }

  //! Compute the hash of the rich header structure encoded with the provided key.
  std::vector<uint8_t> hash(ALGORITHMS algo, uint32_t xor_key) const;

  void accept(Visitor& visitor) const override;

  LIEF_API friend std::ostream& operator<<(std::ostream& os, const RichHeader& rich_header);

  private:
  uint32_t key_ = 0;
  entries_t entries_;

};
}
}

#endif

