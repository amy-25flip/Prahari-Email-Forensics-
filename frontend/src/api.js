import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 90000,
  headers: {
    'X-Requested-With': 'Email-Threat-Detection'
  }
})

export default api
