#pragma once
#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace pacetun
{
  inline std::size_t edge_address_index(std::size_t count, std::uint64_t dial_number,
                                        std::size_t attempt, bool enabled)
  {
    if (count == 0 || attempt >= count)
      throw std::out_of_range("edge address index");
    return enabled ? ((dial_number % count + attempt) % count) : attempt;
  }
}
