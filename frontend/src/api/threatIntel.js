import { apiFetch } from './client';

export const getThreatArticles = async (page = 1, limit = 20) => {
  const response = await apiFetch(`/api/threat-intel/articles?page=${page}&limit=${limit}`);
  if (!response.ok) throw new Error('Failed to fetch threat articles');
  return response.json();
};

export const getThreatCorrelations = async (page = 1, limit = 100) => {
  const response = await apiFetch(`/api/threat-intel/correlations?page=${page}&limit=${limit}`);
  if (!response.ok) throw new Error('Failed to fetch threat correlations');
  return response.json();
};

export const refreshThreatFeed = async () => {
  const response = await apiFetch('/api/threat-intel/refresh', { method: 'POST' });
  if (!response.ok) throw new Error('Failed to refresh threat feed');
  return response.json();
};

export const getDataBreaches = async (page = 1, limit = 20) => {
  const response = await apiFetch(`/api/threat-intel/data-breaches?page=${page}&limit=${limit}`);
  if (!response.ok) throw new Error('Failed to fetch data breaches');
  return response.json();
};

export const getDataBreachSummary = async () => {
  const response = await apiFetch('/api/threat-intel/data-breaches/summary');
  if (!response.ok) throw new Error('Failed to fetch data breach summary');
  return response.json();
};

export const getDataBreach = async (breachId) => {
  const response = await apiFetch(`/api/threat-intel/data-breaches/${breachId}`);
  if (!response.ok) throw new Error('Failed to fetch data breach');
  return response.json();
};

export const collectDataBreaches = async () => {
  const response = await apiFetch('/api/threat-intel/collect/breaches', { method: 'POST' });
  if (!response.ok) throw new Error('Failed to collect data breaches');
  return response.json();
};
