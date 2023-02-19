#pragma once

#include <string>
#include <vector>
#include <functional>
#include <initializer_list>

using ptr_t = uint64_t;

// Rebase address
#define MAKE_PTR(T, pRVA, base)           (T)((ptr_t)pRVA + (ptr_t)base)
#define REBASE(pRVA, baseOld, baseNew)       ((ptr_t)pRVA - (ptr_t)baseOld + (ptr_t)baseNew)

class pattern_search
{
public:
	/// <summary>
	/// Callback to handle a matching address for the Search*WithHandler() methods.
	/// If the handler returns true, the search is stopped, else the search continues.
	/// </summary>
	typedef std::function<bool(ptr_t)> MatchHandler;

public:
	// logAlignment can be used to speed-up the search in some cases. For example, if you know that the start of the pattern
	// is always 8-byte-aligned, you can pass logAlignment=3 (2^3 = 8) to skip searching at all addresses that aren't multiples
	// of 8. Note that for smaller alignments and depending on the exact pattern, this may not always be faster (it may even be
	// a tiny bit slower), so profile it if you care about performance.
	pattern_search(const std::vector<uint8_t> &pattern, size_t logAlignment = 0);
	pattern_search(const std::initializer_list<uint8_t> &&pattern, size_t logAlignment = 0);
	pattern_search(const std::string &pattern, size_t logAlignment = 0);
	pattern_search(const char *pattern, size_t len = 0, size_t logAlignment = 0);
	pattern_search(const uint8_t *pattern, size_t len = 0, size_t logAlignment = 0);

	~pattern_search() = default;




	/// <summary>
	/// Default pattern matching with wildcards and a callback handler for matches.
	/// std::search is approximately 2x faster than naive approach.
	/// </summary>
	/// <param name="wildcard">Pattern wildcard</param>
	/// <param name="scanStart">Starting address</param>
	/// <param name="scanSize">Size of region to scan</param>
	/// <param name="handler">Callback that is called for every match. If it returns true, the search is stopped prematurely.</param>
	/// <param name="value_offset">Value that will be added to resulting addresses</param>
	/// <returns>true if the callback handler ever returned true (i.e. the search ended prematurely), false otherwise.</returns>
	bool search_with_handler(
		uint8_t wildcard,
		void *scanStart,
		size_t scanSize,
		MatchHandler handler,
		ptr_t value_offset = 0
	) const;

	/// <summary>
	/// Full pattern match, no wildcards, with a callback handler for matches.
	/// Uses Boyerspool algorithm.
	/// </summary>
	/// <param name="scanStart">Starting address</param>
	/// <param name="scanSize">Size of region to scan</param>
	/// <param name="handler">Callback that is called for every match. If it returns true, the search is stopped prematurely.</param>
	/// <param name="value_offset">Value that will be added to resulting addresses</param>
	/// <returns>true if the callback handler ever returned true (i.e. the search ended prematurely), false otherwise.</returns>
	bool search_with_handler(
		void *scanStart,
		size_t scanSize,
		MatchHandler handler,
		ptr_t value_offset = 0
	) const;


	/// <summary>
	/// Default pattern matching with wildcards.
	/// std::search is approximately 2x faster than naive approach.
	/// </summary>
	/// <param name="wildcard">Pattern wildcard</param>
	/// <param name="scanStart">Starting address</param>
	/// <param name="scanSize">Size of region to scan</param>
	/// <param name="out">Found results</param>
	/// <param name="value_offset">Value that will be added to resulting addresses</param>
	/// <param name="maxMatches">Maximum number of matches to collect</param>
	/// <returns>Number of found addresses</returns>
	size_t search(
		uint8_t wildcard,
		void *scanStart,
		size_t scanSize,
		std::vector<ptr_t> &out,
		ptr_t value_offset = 0,
		size_t maxMatches = SIZE_MAX
	) const;

	/// <summary>
	/// Full pattern match, no wildcards.
	/// Uses Boyerorspool algorithm.
	/// </summary>
	/// <param name="scanStart">Starting address</param>
	/// <param name="scanSize">Size of region to scan</param>
	/// <param name="out">Found results</param>
	/// <param name="value_offset">Value that will be added to resulting addresses</param>
	/// <param name="maxMatches">Maximum number of matches to collect</param>
	/// <returns>Number of found addresses</returns>
	size_t search(
		void *scanStart,
		size_t scanSize,
		std::vector<ptr_t> &out,
		ptr_t value_offset = 0,
		size_t maxMatches = SIZE_MAX
	) const;

private:
	static inline bool collectAllMatchHandler(ptr_t addr, std::vector<ptr_t> &out, size_t maxMatches)
	{
		out.emplace_back(addr);
		return out.size() >= maxMatches;
	}

private:
	std::vector<uint8_t> _pattern;      // Pattern to search
	size_t logAlignment;

public:
	/// <summary>
	/// Callback to handle a matching address for the Search*WithHandler() methods.
	/// If the handler returns true, the search is stopped, else the search continues.
	/// </summary>
	typedef std::function<bool(ptr_t)> MatchHandler;
};
