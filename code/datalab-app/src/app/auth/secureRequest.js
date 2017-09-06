import request from 'axios';
import auth from './auth';

request.interceptors.request.use((requestConfig) => {
  const currentSession = auth.getCurrentSession();
  return {
    ...requestConfig,
    headers: {
      ...requestConfig.headers,
      Authorization: `Bearer ${currentSession.accessToken}`,
    },
  };
});

request.interceptors.response.use(
  undefined, // No intercept for good responses
  (error) => {
    // This intercept will catch 401 responses for requests with expired bearer token to the API and attempt to renew
    // access token and reissue the request. Failed unauthorized posts will appear as an error in the console log.
    const requestValue = error.config;
    const responseValue = error.response;
    if (responseValue && responseValue.status === 401 && requestValue.method === 'post' && !requestValue.isRetryRequest) {
      return new Promise((resolve, reject) => {
        // Add tag to reissued request to prevent looping
        requestValue.isRetryRequest = true;
        auth.renewSession()
          .then(() => resolve(request(requestValue)))
          .catch(authErr => reject(authErr));
      });
    }
    return Promise.reject(error);
  });

export default request;