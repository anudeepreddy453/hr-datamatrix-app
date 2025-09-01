/**
 * Utility functions for Indian Standard Time (IST) formatting
 * Manually adds 6 hours and 30 minutes to current time for IST
 */

/**
 * Add IST offset (5 hours 30 minutes) to a date
 * @param {Date} date - Date object
 * @returns {Date} Date with IST offset added
 */
const addISTOffset = (date) => {
  const istDate = new Date(date);
  istDate.setHours(istDate.getHours() + 5);
  istDate.setMinutes(istDate.getMinutes() + 30);
  return istDate;
};

/**
 * Format a date string to Indian Standard Time
 * @param {string} dateString - ISO date string
 * @param {boolean} includeSeconds - Whether to include seconds in the output
 * @returns {string} Formatted Indian time string
 */
export const formatIndianTime = (dateString, includeSeconds = true) => {
  try {
    const date = new Date(dateString);
    const istDate = addISTOffset(date);
    
    const options = {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: true
    };
    
    if (includeSeconds) {
      options.second = '2-digit';
    }
    
    return istDate.toLocaleString('en-IN', options);
  } catch (error) {
    console.error('Error formatting Indian time:', error);
    return dateString;
  }
};

/**
 * Format current time in Indian Standard Time
 * @param {boolean} includeSeconds - Whether to include seconds in the output
 * @returns {string} Current Indian time string
 */
export const getCurrentIndianTime = (includeSeconds = true) => {
  const now = new Date();
  const istNow = addISTOffset(now);
  
  const options = {
    hour: '2-digit',
    minute: '2-digit',
    hour12: true
  };
  
  if (includeSeconds) {
    options.second = '2-digit';
  }
  
  return istNow.toLocaleString('en-IN', options);
};

/**
 * Format date only in Indian Standard Time
 * @param {string} dateString - ISO date string
 * @returns {string} Formatted Indian date string
 */
export const formatIndianDate = (dateString) => {
  try {
    const date = new Date(dateString);
    const istDate = addISTOffset(date);
    
    return istDate.toLocaleDateString('en-IN', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      weekday: 'long'
    });
  } catch (error) {
    console.error('Error formatting Indian date:', error);
    return dateString;
  }
};

/**
 * Get timezone offset for India
 * @returns {string} Timezone offset string (e.g., "+05:30")
 */
export const getIndianTimezoneOffset = () => {
  return '+05:30'; // Fixed IST offset
};

/**
 * Check if a date is today in Indian timezone
 * @param {string} dateString - ISO date string
 * @returns {boolean} True if the date is today
 */
export const isTodayInIndia = (dateString) => {
  try {
    const date = new Date(dateString);
    const istDate = addISTOffset(date);
    const now = new Date();
    const istNow = addISTOffset(now);
    
    const istDateStr = istDate.toLocaleDateString('en-IN');
    const istNowStr = istNow.toLocaleDateString('en-IN');
    
    return istDateStr === istNowStr;
  } catch (error) {
    console.error('Error checking if date is today in India:', error);
    return false;
  }
};

/**
 * Get relative time in Indian context (e.g., "2 hours ago", "yesterday")
 * @param {string} dateString - ISO date string
 * @returns {string} Relative time string
 */
export const getRelativeIndianTime = (dateString) => {
  try {
    const date = new Date(dateString);
    const istDate = addISTOffset(date);
    const now = new Date();
    const istNow = addISTOffset(now);
    
    const diffMs = istNow - istDate;
    const diffMins = Math.floor(diffMs / (1000 * 60));
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
    if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
    
    return formatIndianDate(dateString);
  } catch (error) {
    console.error('Error getting relative Indian time:', error);
    return formatIndianTime(dateString);
  }
};

/**
 * Get current IST date and time for display
 * @returns {object} Object with date and time strings
 */
export const getCurrentISTDateTime = () => {
  const now = new Date();
  const istNow = addISTOffset(now);
  
  return {
    date: istNow.toLocaleDateString('en-IN', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      weekday: 'long'
    }),
    time: istNow.toLocaleTimeString('en-IN', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: true
    }),
    fullDateTime: istNow.toLocaleString('en-IN', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: true
    })
  };
};
