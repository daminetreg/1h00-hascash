/*
    ver: Hashcash format version, 1 (which supersedes version 0).
    bits: Number of "partial pre-image" (zero) bits in the hashed code.
    date: The time that the message was sent, in the format YYMMDD[hhmm[ss]].
    resource: Resource data string being transmitted, e.g., an IP address or email address.
    ext: Extension (optional; ignored in version 1).
    rand: String of random characters, encoded in base-64 format.
    counter: Binary counter (up to 220), encoded in base-64 format.
*/

/*

   Sender's side

The sender prepares a header and appends a counter value initialized to a random number. It then computes the 160-bit SHA-1 hash of the header. If the first 20 bits of the hash are all zeros, then this is an acceptable header. If not, then the sender increments the counter and tries the hash again. Out of 2160 possible hash values, there are 2140 hash values that satisfy this criterion. Thus the chance of randomly selecting a header that will have 20 zeros as the beginning of the hash is 1 in 220. The number of times that the sender needs to try before getting a valid hash value is modeled by geometric distribution. Hence the sender will on average have to try 219 or at worst more than a million counter values to find a valid header. Given reasonable estimates of the time needed to compute the hash,[when?] this would take about 1 second to find. At this time, no more efficient method is known to find a valid header.

A normal user on a desktop PC would not be significantly inconvenienced by the processing time required to generate the Hashcash string. However, spammers would suffer significantly due to the large number of spam messages sent by them.
*/


#include <iostream>
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
  size_t prefix_bits = 20;

  rule<decltype(strout)> gen_date = lit("BOOM"); //TODO: Date formatting
  rule<decltype(strout)> gen = int_(hashcash_ver) 
    << ':' << int_[_1 = phx::ref(prefix_bits)]
    << ':' << gen_date//[_1 = phx::ref(date)]
    << ':' << ascii::string[_1 = phx::ref(resource)]
    << ':'
    << ':' << ascii::string[_1 = base64::encode(randomness)]
    << ':' << ascii::string[_1 = base64::encode(std::to_string(counter))]
  ;

 
  auto r = generate(strout, gen);
  assert(!r); //Generation should never fail

  return str;
}

int main(int argc, char** argv) {
	std::string a = "Franz jagt im komplett verwahrlosten Taxi quer durch Bayern";

  std::cout << base64::encode(a) << std::endl;
  std::cout << sha1::hash(a) << std::endl;

  std::cout << "X-Hashcash:" << hashcash_output(std::time(nullptr), argv[1], "42", 1) << std::endl;


  return 0;
}
