/*
    ver: Hashcash format version, 1 (which supersedes version 0).
    bits: Number of "partial pre-image" (zero) bits in the hashed code.
    date: The time that the message was sent, in the format YYMMDD[hhmm[ss]].
    resource: Resource data string being transmitted, e.g., an IP address or email address.
    ext: Extension (optional; ignored in version 1).
    rand: String of random characters, encoded in base-64 format.
    counter: Binary counter (up to 220), encoded in base-64 format.
*/


#include <iostream>
#include <algorithm>
#include <boost/uuid/sha1.hpp>

#include <cstdio>
#include <cassert>
#include <string>
#include <base64.hpp>
#include <sha1.hpp>

#include <boost/spirit/include/karma.hpp>
#include <boost/spirit/include/karma_string.hpp>
#include <boost/spirit/include/phoenix.hpp>
#include <boost/spirit/include/qi.hpp>



const int hashcash_ver = 1;
const size_t counter_max = 0x100000 - 1; 
const size_t prefix_bits = 20;

/*
    ver: Hashcash format version, 1 (which supersedes version 0).
    bits: Number of "partial pre-image" (zero) bits in the hashed code.
    date: The time that the message was sent, in the format YYMMDD[hhmm[ss]].
    resource: Resource data string being transmitted, e.g., an IP address or email address.
    ext: Extension (optional; ignored in version 1).
    rand: String of random characters, encoded in base-64 format.
    counter: Binary counter (up to 220), encoded in base-64 format.
*/
std::string hashcash_output(std::time_t date, const std::string& resource, const std::string& randomness, size_t counter) {
  using namespace boost::spirit::karma;
  namespace phx = boost::phoenix;

  using ascii::string;

  std::string str;
  std::back_insert_iterator<std::string> strout{str};

  rule<decltype(strout)> gen_date = lit("170904"); //TODO: Date formatting
  rule<decltype(strout)> gen = int_(hashcash_ver) 
    << ':' << int_[_1 = phx::ref(prefix_bits)]
    << ':' << gen_date//[_1 = phx::ref(date)]
    << ':' << ascii::string[_1 = phx::ref(resource)]
    << ':'
    << ':' << ascii::string[_1 = base64::encode(randomness)]
    << ':' << ascii::string[_1 = base64::encode(std::to_string(counter))]
  ;

 
  auto r = generate(strout, gen);
  assert(r); //Generation should never fail

  return str;
}


struct hashcash {
  std::time_t date;
  std::string resource; 
  std::string randomness;
  size_t counter;
};

/*

   Sender's side

The sender prepares a header and appends a counter value initialized to a random number. It then computes the 160-bit SHA-1 hash of the header. If the first 20 bits of the hash are all zeros, then this is an acceptable header. If not, then the sender increments the counter and tries the hash again. Out of 2160 possible hash values, there are 2140 hash values that satisfy this criterion. Thus the chance of randomly selecting a header that will have 20 zeros as the beginning of the hash is 1 in 220. The number of times that the sender needs to try before getting a valid hash value is modeled by geometric distribution. Hence the sender will on average have to try 219 or at worst more than a million counter values to find a valid header. Given reasonable estimates of the time needed to compute the hash,[when?] this would take about 1 second to find. At this time, no more efficient method is known to find a valid header.

A normal user on a desktop PC would not be significantly inconvenienced by the processing time required to generate the Hashcash string. However, spammers would suffer significantly due to the large number of spam messages sent by them.
*/
void hashcash_gen(hashcash& hc) {

  std::srand(hc.date); // use current time as seed for random generator
  hc.counter = std::min<size_t>(std::rand(), counter_max);

  int randomness = std::rand();
  std::string randomness_buf(reinterpret_cast<const char*>(&randomness), sizeof randomness);
  hc.randomness = "hello";//randomness_buf;//sha1::to_string(sha1::hash(randomness_buf));

  std::array<uint32_t, 5> hash;
  do {
  
    hash = sha1::hash(hashcash_output(hc.date, hc.resource, hc.randomness, hc.counter));
    std::cout << "My hash : " << sha1::to_string(hash) << std::endl; 
    std::cout << hashcash_output(hc.date, hc.resource, hc.randomness, hc.counter) << std::endl;

    std::srand(std::time(0));
    if ( (hash[0] & 0xFFFFF000) != 0 ) {
      hc.counter = (hc.counter == counter_max) ? 0 : std::min<size_t>(hc.counter + 1, counter_max);
      std::cout << "Current counter : " << hc.counter << std::endl;
    } else {
      return;
    }
  } while ( true );
}

bool check_hashcash(const std::string& hashcash_str) {
  std::array<uint32_t, 5> hash;
  hash = sha1::hash(hashcash_str);
  std::cout << "Hash we do compute : " << sha1::to_string(hash) << std::endl;
  return ( (hash[0] & 0xFFFFF000) == 0 ); 
}


int main(int argc, char** argv) {
  if (std::string(argv[1]) == "check") {
    if (check_hashcash(argv[2])) {
      std::cout << "It's a valid one !" << std::endl;
      std::cout << "It's a valid one !" << std::endl;
      std::cout << "It's a valid one !" << std::endl;
    } else {
      std::cout << "Sorry not good!";
    }
    return 0;
  }

	std::string a = "Franz jagt im komplett verwahrlosten Taxi quer durch Bayern";

  std::cout << base64::encode(a) << std::endl;
  std::cout << sha1::to_string(sha1::hash(a)) << std::endl;

  std::cout << "X-Hashcash:" << hashcash_output(std::time(nullptr), argv[1], "42", 1) << std::endl;

  hashcash hc;
  hc.date = std::time(nullptr);
  hc.resource = argv[1];
  hashcash_gen(hc);

  std::cout << hashcash_output(hc.date, hc.resource, hc.randomness, hc.counter) << std::endl;

  return 0;
}
