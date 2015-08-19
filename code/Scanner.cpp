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

Scanner::Scanner(const bool honourTimeLimits)
: m_HonourLimit(honourTimeLimits),
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
    std::clog << "Waiting " << std::chrono::duration_cast<std::chrono::seconds>(duration).count()
              << " second(s) for time limit to expire..." << std::endl;
    std::this_thread::sleep_for(duration);
  } //if waiting is required
}
