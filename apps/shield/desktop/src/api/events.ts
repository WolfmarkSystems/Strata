import { listen } from '@tauri-apps/api/event';
import { api } from './tauri';
import type { EngineEvent } from '../types';

const MAX_EVENTS = 500;

class EventStore {
  private events: EngineEvent[] = [];
  private listeners: Set<(events: EngineEvent[]) => void> = new Set();
  private initialized = false;

  async init(caseId?: string) {
    if (this.initialized) return;
    
    try {
      const buffer = await api.getEventBuffer(caseId, 200);
      this.events = buffer.slice(0, MAX_EVENTS);
      this.notify();
    } catch (e) {
      console.warn('Failed to load event buffer:', e);
    }

    listen<EngineEvent>('engine_event', (event) => {
      this.addEvent(event.payload);
    });

    this.initialized = true;
  }

  addEvent(event: EngineEvent) {
    this.events.unshift(event);
    if (this.events.length > MAX_EVENTS) {
      this.events = this.events.slice(0, MAX_EVENTS);
    }
    this.notify();
  }

  getEvents(): EngineEvent[] {
    return [...this.events];
  }

  subscribe(listener: (events: EngineEvent[]) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notify() {
    const current = this.getEvents();
    this.listeners.forEach(listener => listener(current));
  }

  filter(severity?: string, kind?: string, search?: string): EngineEvent[] {
    return this.events.filter(e => {
      if (severity && e.severity !== severity) return false;
      if (kind && !(e.kind?.type || '').includes(kind)) return false;
      if (search && !(e.message || '').toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }

  clear() {
    this.events = [];
    this.notify();
  }
}

export const eventStore = new EventStore();
