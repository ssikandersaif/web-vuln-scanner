"""
Rate Limiter - Controls how fast we send requests
=================================================

Think of this like a speed limit for your car:
- Without limit: You drive 200 mph and crash
- With limit: You drive 60 mph and arrive safely

This helps us:
1. Not crash the target website
2. Not get blocked by firewalls
3. Look like a normal user, not an attacker
"""

import time


class RateLimiter:
    """
    Controls how fast we send requests.
    
    Example:
        limiter = RateLimiter(delay=0.5, max_per_url=10)
        
        # Before each request:
        if limiter.can_request(url):
            limiter.wait()  # Pauses if needed
            # ... send request ...
    """
    
    def __init__(self, delay=0.5, max_per_url=20):
        """
        Set up the rate limiter.
        
        Args:
            delay: Seconds to wait between requests (default: 0.5)
            max_per_url: Maximum requests allowed per URL (default: 20)
        """
        self.delay = delay
        self.max_per_url = max_per_url
        
        # Track when we last made a request
        self.last_request_time = 0
        
        # Track how many requests we've made to each URL
        # Example: {"/login": 5, "/search": 3}
        self.request_counts = {}
        
        # Total requests made
        self.total_requests = 0
    
    def wait(self):
        """
        Wait if we're going too fast.
        
        This is like a traffic light - it makes you
        stop and wait before you can go again.
        """
        # How long since last request?
        time_since_last = time.time() - self.last_request_time
        
        # If not enough time has passed, wait
        if time_since_last < self.delay:
            wait_time = self.delay - time_since_last
            time.sleep(wait_time)
        
        # Update the last request time
        self.last_request_time = time.time()
    
    def can_request(self, url):
        """
        Check if we're allowed to request this URL.
        
        Returns:
            True if we can make the request
            False if we've hit the limit for this URL
        """
        # Get just the path part of URL for tracking
        # "http://localhost:8080/login" -> "/login"
        path = self._get_path(url)
        
        # How many times have we requested this?
        count = self.request_counts.get(path, 0)
        
        # Check if we've hit the limit
        if count >= self.max_per_url:
            return False
        
        return True
    
    def record_request(self, url):
        """
        Record that we made a request to this URL.
        
        Call this AFTER making each request.
        """
        path = self._get_path(url)
        
        # Increment the count for this URL
        if path in self.request_counts:
            self.request_counts[path] += 1
        else:
            self.request_counts[path] = 1
        
        self.total_requests += 1
    
    def _get_path(self, url):
        """
        Extract the path from a URL.
        
        "http://localhost:8080/vulnerabilities/sqli/" -> "/vulnerabilities/sqli/"
        """
        # Find where the path starts (after ://)
        if "://" in url:
            # Remove http://hostname part
            without_protocol = url.split("://", 1)[1]
            # Find the first / after hostname
            if "/" in without_protocol:
                path = "/" + without_protocol.split("/", 1)[1]
            else:
                path = "/"
        else:
            path = url
        
        return path
    
    def get_stats(self):
        """
        Get statistics about requests made.
        
        Returns a dictionary with stats.
        """
        return {
            "total_requests": self.total_requests,
            "urls_visited": len(self.request_counts),
            "requests_per_url": dict(self.request_counts)
        }


# Create a default rate limiter that everyone can use
default_limiter = RateLimiter(delay=0.3, max_per_url=20)


def rate_limited_request(session, method, url, **kwargs):
    """
    Make a request with rate limiting built in.
    
    This is a helper function that:
    1. Checks if we can make the request
    2. Waits if we're going too fast
    3. Makes the request
    4. Records it
    
    Args:
        session: The requests session
        method: "GET" or "POST"
        url: The URL to request
        **kwargs: Extra arguments (params, data, etc.)
    
    Returns:
        The response, or None if we hit the limit
    
    Example:
        response = rate_limited_request(session, "GET", url, params={"id": "1"})
        response = rate_limited_request(session, "POST", url, data={"user": "admin"})
    """
    # Check if we're allowed
    if not default_limiter.can_request(url):
        print(f"    [!] Rate limit reached for {url}")
        return None
    
    # Wait if needed
    default_limiter.wait()
    
    # Make the request
    if method.upper() == "POST":
        response = session.post(url, **kwargs)
    else:
        response = session.get(url, **kwargs)
    
    # Record it
    default_limiter.record_request(url)
    
    return response
