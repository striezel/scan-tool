/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015  Thoronador

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 -------------------------------------------------------------------------------
*/

#include "Scanner.hpp"
#include <iostream>
#include <thread>

Scanner::Scanner(const bool honourTimeLimits, const bool _silent)
: m_HonourLimit(honourTimeLimits),
  m_Silent(_silent),
  //We assume that time limit will not be higher than 24 hours.
  m_LastRequest(std::chrono::steady_clock::now() - std::chrono::hours(24))
{ }

bool Scanner::honoursTimeLimit() const
{
  return m_HonourLimit;
}

void Scanner::honourTimeLimit(const bool doHonour)
{
  m_HonourLimit = doHonour;
}

bool Scanner::silent() const
{
  return m_Silent;
}

void Scanner::silence(const bool silent)
{
  m_Silent = silent;
}

std::chrono::steady_clock::time_point Scanner::lastRequestTime() const
{
  return m_LastRequest;
}

void Scanner::requestWasNow()
{
  m_LastRequest = std::chrono::steady_clock::now();
}

void Scanner::waitForLimitExpiration()
{
  //If time limit is not honoured, we can exit here.
  if (!honoursTimeLimit())
    return;

  const auto now_steady = std::chrono::steady_clock::now();
  if (m_LastRequest + timeBetweenConsecutiveRequests() > now_steady)
  {
    const auto duration = m_LastRequest + timeBetweenConsecutiveRequests() - now_steady;
    if (!m_Silent)
    {
      std::clog << "Waiting ";
      if (duration >= std::chrono::seconds(2))
        std::clog << std::chrono::duration_cast<std::chrono::seconds>(duration).count()
                  << " seconds for time limit to expire..." << std::endl;
      else
        std::clog << std::chrono::duration_cast<std::chrono::milliseconds>(duration).count()
                  << " millisecond(s) for time limit to expire..." << std::endl;
    } //if not silent
    std::this_thread::sleep_for(duration);
  } //if waiting is required
}
