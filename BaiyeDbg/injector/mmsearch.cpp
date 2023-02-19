#include "mmsearch.h"

BOOLEAN MmsCompare(UINT8 Wildcard, PUINT8 ScanBuffer, PUINT8 PatternBuffer, SIZE_T CompareSize)
{
	for (SIZE_T index = 0; index < CompareSize; ++index)
	{
		if (PatternBuffer[index] != Wildcard && ScanBuffer[index] != PatternBuffer[index])
		{
			return FALSE;
		}
	}

	return TRUE;
}

BOOLEAN MmsSerch(
	UINT8			Wildcard,
	const PUINT8	ScanStart,
	SIZE_T			ScanSize,
	const PUINT8	Pattern,
	SIZE_T			PatternSize,
	IN OUT PVOID	*FoundAddress,
	IN OUT SIZE_T	*MaxFoundSize)
{
	if (ScanSize > MAXSIZE_T)
	{
		return FALSE;
	}

	SIZE_T FoundCount = 0;

	PUINT8 ScanStart0 = ScanStart;

	for (SIZE_T StartIndex = 0; StartIndex < ScanSize; ++StartIndex)
	{
		if (MmsCompare(Wildcard, &ScanStart0[StartIndex], Pattern, PatternSize))
		{
			FoundAddress[FoundCount] = &ScanStart0[StartIndex];
			++FoundCount;
		}

		if (FoundCount  >= *MaxFoundSize)
		{
			break;
		}
	}

	*MaxFoundSize = FoundCount;

	return (FoundCount > 0);
}