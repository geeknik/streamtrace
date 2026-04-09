import { createStore } from "solid-js/store";
import type { Case, CaseDetail } from "../api/types";

export interface CasesState {
  cases: Case[];
  loading: boolean;
  error: string | null;
  selectedCase: CaseDetail | null;
  selectedCaseLoading: boolean;
}

const initialState: CasesState = {
  cases: [],
  loading: false,
  error: null,
  selectedCase: null,
  selectedCaseLoading: false,
};

export const [casesState, setCasesState] =
  createStore<CasesState>(initialState);
