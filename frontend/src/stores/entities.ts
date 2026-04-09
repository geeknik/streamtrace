import { createStore } from "solid-js/store";
import type { Entity } from "../api/types";

export interface EntityState {
  entities: Entity[];
  selectedEntityId: string | null;
  typeFilter: string;
  loading: boolean;
}

const initialState: EntityState = {
  entities: [],
  selectedEntityId: null,
  typeFilter: "",
  loading: false,
};

export const [entityState, setEntityState] =
  createStore<EntityState>(initialState);
