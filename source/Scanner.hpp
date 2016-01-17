/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015, 2016  Thoronador

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

#ifndef SCANNER_HPP
#define SCANNER_HPP

#include <chrono>
#include <cstdint>

class Scanner
{
  public:
    /** \brief default constructor
     *
     * \param honourTimeLimits   whether or not time limits should be honoured
     * \param _silent            whether or not output to the standard output should be reduced
     */
    Scanner(const bool honourTimeLimits = true, const bool _silent=false);


    ///virtual destructor
    virtual ~Scanner() {}


    /** \brief checks, if this scanner respects its time limit
     *
     * \return True, if time limit is considered between requests.
     *         Returns false, if not.
     */
    bool honoursTimeLimit() const;


     /** \brief set, if time limit is considered between two requests
      *
      * \param doHonour   new value that determines whether time limits matter
      */
    void honourTimeLimit(const bool doHonour);


    /** \brief checks whether the scanner is silent or not
     *
     * \return Returns true, if the scanner is silent.
     * \remarks "Silent" means that the Scanner produces as little output as
     * possible on the standard output - except for hard errors.
     */
    bool silent() const;


    /** \brief set the new silence mode
     *
     * \param silent  If true, the scanner will be silent.
     */
    void silence(const bool silent);


    /** \brief duration between consecutive file scan requests, if time limit is respected
     *
     * \return Returns the minimum interval between two consecutive file scan requests.
     */
    virtual std::chrono::milliseconds timeBetweenConsecutiveScanRequests() const = 0;


    /** \brief duration between consecutive hash lookups, if time limit is respected
     *
     * \return Returns the minimum interval between two consecutive hash lookups.
     */
    virtual std::chrono::milliseconds timeBetweenConsecutiveHashLookups() const = 0;


    /** \brief returns the time of the last scan request
     *
     * \return Returns the time of the last scan request.
     */
    std::chrono::steady_clock::time_point lastScanRequestTime() const;


    /** \brief returns the time of the last hash lookup
     *
     * \return Returns the time of the last hash lookup.
     */
    std::chrono::steady_clock::time_point lastHashLookupTime() const;


    /** \brief sets the time of the last request to now
     */
    virtual void scanRequestWasNow();


    /** \brief sets the time of the last hash lookup to now
     */
    virtual void hashLookupWasNow();


    /** \brief waits until the time limit for file scans has expired, if the
     *         scanner honours a time limit
     */
    void waitForScanLimitExpiration();


    /** \brief waits until the time limit for hash lookups has expired, if the
     *         scanner honours a time limit
     */
    void waitForHashLookupLimitExpiration();


     /** \brief returns the maximum file size that is allowed to be scanned
      *
      * \return maximum size in bytes that can still be scanned
      */
    virtual int64_t maxScanSize() const = 0;
  private:
    bool m_HonourLimit; /**< whether to honour time limits */
    bool m_Silent; /**< whether to be silent */
  protected:
    /* Both time points are protected and not private, because descendants might
       need to modify them directly in overridden scanRequestWasNow() or
       hashLookupWasNow() methods. */
    std::chrono::steady_clock::time_point m_LastScanRequest; /**< time of the last scan request */
    std::chrono::steady_clock::time_point m_LastHashLookup; /**< time of the last hash lookup */
}; //class

#endif // SCANNER_HPP
