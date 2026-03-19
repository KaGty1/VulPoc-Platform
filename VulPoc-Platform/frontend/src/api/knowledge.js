import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1',
})

function unwrap(response) {
  return response?.data?.data
}

export async function searchEntries(params) {
  const response = await api.get('/entries', { params })
  return unwrap(response) || { list: [], total: 0, page: 1, page_size: 12 }
}

export async function fetchEntry(id) {
  const response = await api.get(`/entries/${id}`)
  return unwrap(response)
}

export async function fetchSources() {
  const response = await api.get('/sources')
  return unwrap(response) || []
}

export async function fetchTags() {
  const response = await api.get('/tags')
  return unwrap(response) || []
}

export async function fetchStats() {
  const response = await api.get('/stats')
  return unwrap(response) || {}
}
