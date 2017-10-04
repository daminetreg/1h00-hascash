#ifndef SHA1_HPP
#define SHA1_HPP

#include <boost/uuid/sha1.hpp>

namespace sha1 {
  std::string hash(const std::string& p_arg) {
      boost::uuids::detail::sha1 sha1;
      sha1.process_bytes(p_arg.data(), p_arg.size());
      uint32_t hash[5] = {0};
      sha1.get_digest(hash);

      // Back to string
      char buf[41] = {0};

      for (int i = 0; i < 5; i++)
      {
          std::sprintf(buf + (i << 3), "%08x", hash[i]);
      }

      return std::string(buf);
  }

}

#endif
