#include "mem_search.h"

#include <algorithm>
#include <memory>

pattern_search::pattern_search(const std::vector<uint8_t> &pattern, size_t logAlignment /*= 0*/)
	: _pattern(pattern), logAlignment(logAlignment)
{
}

pattern_search::pattern_search(const std::initializer_list<uint8_t> &&pattern, size_t logAlignment /*= 0*/)
	: _pattern(pattern), logAlignment(logAlignment)
{
}

pattern_search::pattern_search(const std::string &pattern, size_t logAlignment /*= 0*/)
	: _pattern(pattern.begin(), pattern.end()), logAlignment(logAlignment)
{
}

pattern_search::pattern_search(const char *pattern, size_t len /*= 0*/, size_t logAlignment /*= 0*/)
	: _pattern(pattern, pattern + (len ? len : strlen(pattern))), logAlignment(logAlignment)
{
}

pattern_search::pattern_search(const uint8_t *pattern, size_t len /*= 0*/, size_t logAlignment /*= 0*/)
	: _pattern(pattern, pattern + (len ? len : strlen((const char *)pattern))), logAlignment(logAlignment)
{
}



bool pattern_search::search_with_handler(
	uint8_t wildcard,
	void *scanStart,
	size_t scanSize,
	MatchHandler handler,
	ptr_t value_offset
) const
{
	const uint8_t *cstart = (const uint8_t *)scanStart;
	const uint8_t *cend = cstart + scanSize;

	// TODO: Would it be beneficial to use logAlignment here as well?

	auto comparer = [&wildcard](uint8_t val1, uint8_t val2)
	{
		return (val1 == val2 || val2 == wildcard);
	};

	bool running = true;
	while (running)
	{
		const uint8_t *res = std::search(cstart, cend, _pattern.begin(), _pattern.end(), comparer);
		if (res >= cend)
			break;

		if (value_offset != 0)
			running = !handler(REBASE(res, scanStart, value_offset));
		//out.emplace_back( REBASE( res, scanStart, value_offset ) );
		else
			//out.emplace_back( reinterpret_cast<ptr_t>(res) );
			running = !handler(reinterpret_cast<ptr_t>(res));

		cstart = res + _pattern.size();
	}

	return !running;
}

/// <summary>
/// Full pattern match, no wildcards, with a callback handler for matches.
/// Uses Boyerspool algorithm.
/// </summary>
/// <param name="scanStart">Starting address</param>
/// <param name="scanSize">Size of region to scan</param>
/// <param name="handler">Callback that is called for every match. If it returns true, the search is stopped prematurely.</param>
/// <param name="value_offset">Value that will be added to resulting addresses</param>
/// <returns>true if the callback handler ever returned true (i.e. the search ended prematurely), false otherwise.</returns>
bool pattern_search::search_with_handler(
	void *scanStart,
	size_t scanSize,
	MatchHandler handler,
	ptr_t value_offset
) const
{
	size_t bad_char_skip[UCHAR_MAX + 1];

	const uint8_t *haystack = reinterpret_cast<const uint8_t *>(scanStart);
	const uint8_t *haystackEnd = haystack + scanSize - _pattern.size();
	const uint8_t *needle = &_pattern[0];
	uintptr_t       nlen = _pattern.size();
	uintptr_t       scan = 0;
	uintptr_t       last = nlen - 1;
	size_t alignMask = 0xFFFFFFFFFFFFFFFFL << logAlignment;
	size_t alignOffs = (1 << logAlignment) - 1;

	//
	// Preprocess
	//
	for (scan = 0; scan <= UCHAR_MAX; ++scan)
		bad_char_skip[scan] = nlen;

	for (scan = 0; scan < last; ++scan)
		bad_char_skip[needle[scan]] = last - scan;

	//
	// Search
	//
	bool running = true;
	//while (haystack <= haystackEnd  &&  out.size() < maxMatches)
	while (haystack <= haystackEnd && running)
	{
		for (scan = last; haystack[scan] == needle[scan]; --scan)
		{
			if (scan == 0)
			{
				if (value_offset != 0)
					//out.emplace_back( REBASE( haystack, scanStart, value_offset ) );
					running = !handler(REBASE(haystack, scanStart, value_offset));
				else
					//out.emplace_back( reinterpret_cast<ptr_t>(haystack) );
					running = !handler(reinterpret_cast<ptr_t>(haystack));

				break;
			}
		}

		haystack += bad_char_skip[haystack[last]];

		if (logAlignment != 0) {
			haystack = (const uint8_t *)(size_t(haystack + alignOffs) & alignMask);
		}
	}

	return !running;
}





size_t pattern_search::search(
	uint8_t wildcard,
	void *scanStart,
	size_t scanSize,
	std::vector<ptr_t> &out,
	ptr_t value_offset,
	size_t maxMatches
) const
{
	if (out.size() >= maxMatches)
		return out.size();

	auto handler = std::bind(pattern_search::collectAllMatchHandler, std::placeholders::_1, std::ref(out), maxMatches);
	search_with_handler(wildcard, scanStart, scanSize, handler, value_offset);

	return out.size();
}


size_t pattern_search::search(
	void *scanStart,
	size_t scanSize,
	std::vector<ptr_t> &out,
	ptr_t value_offset,
	size_t maxMatches
) const
{
	if (out.size() >= maxMatches)
		return out.size();

	auto handler = std::bind(pattern_search::collectAllMatchHandler, std::placeholders::_1, std::ref(out), maxMatches);
	search_with_handler(scanStart, scanSize, handler, value_offset);

	return out.size();
}
