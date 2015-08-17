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

#ifndef SCANTOOL_CURLY_HPP
#define SCANTOOL_CURLY_HPP

#include <string>
#include <unordered_map>

extern "C"
{
  /** \brief write callback for cURL functions
   */
  size_t writeCallbackString(char *ptr, size_t size, size_t nmemb, void *userdata);
} //extern C

class Curly
{
  public:
    ///default constructor
    Curly();

    /// delete copy constructor
    Curly(const Curly& other) = delete;


    /** \brief sets the new URL for the operation
     *
     * \param newURL   the new URL
     */
    void setURL(const std::string& newURL);


    /** \brief gets the current URL
     *
     * \return Returns the current URL.
     * Returns an empty string, if no URL was set yet.
     */
    const std::string& getURL() const;


    /** \brief adds a field for POST request
     *
     * \param name   name of the field
     * \param value  the field's value
     * \remarks If a POST field with the same name already exists, its value
     *          will be overwritten.
     */
    void addPostField(const std::string& name, const std::string& value);


    /** \brief checks, if this class instance has a POST field with the given name
     *
     * \param name   name of the field
     * \return Returns true, if a field with the given name exists.
     *         Returns false otherwise.
     */
    bool hasPostField(const std::string& name) const;


    /** \brief returns the value of a post field, if it exists
     *
     * \param name  name of the field
     * \return Returns the value of the field, if it exists.
     *         Returns empty string, if the field does not exist.
     * \remarks Note that an empty string can also be a proper return value
     * for an existing field. If you want to check the existence of a certain
     * field, use hasPostField().
     */
    std::string getPostField(const std::string& name) const;


    /** \brief removes a POST field that was previously set
     *
     * \param name   name of the field
     * \return Returns true, if a field with the given name existed and was
     * removed. Returns false, if no such field was present.
     */
    bool removePostField(const std::string& name);


    /** \brief performs the (POST) request
     *
     * \param response  reference to a string that will be filled with the
     *                  request's response
     * \return Returns true, if the request could be performed.
     *         Returns false, if the request was not performed properly.
     *         Note that the value of @arg response is undefined, if the
     *         request failed.
     */
    bool perform(std::string& response);


    /** \brief returns the response code of the last request, or zero (0)
     *
     * \return Returns the response code of the last request.
     *         Returns zero, if no response code was set (e.g. when the
     *         protocol does not provide such a code) or no request was
     *         performed yet.
     */
    long getResponseCode() const;


    /** \brief returns the content type of the last request, or an empty string
     *
     * \return Returns the content type of the last request.
     *         Returns an empty string, if no content type header was received
     *         or no request was performed yet.
     */
    const std::string& getContentType() const;
  private:
    std::string m_URL;
    std::unordered_map<std::string, std::string> m_PostFields;
    long m_LastResponseCode;
    std::string m_LastContentType;
}; //class Curly

#endif // SCANTOOL_CURLY_HPP
