'use client';
import { useActionState } from 'react';
import { deleteInvoice, State } from '@/app/lib/actions';
import { TrashIcon } from '@heroicons/react/24/outline';

type Props = {
  id: string;
};

export default function DeleteInvoiceForm({ id }: Props) {
  const initialState: State = { message: null, errors: {} };
  const deleteInvoiceWithId = deleteInvoice.bind(null, id);
  const [, formAction, pending] = useActionState<State, FormData>(deleteInvoiceWithId, initialState);

  return (
    <form action={formAction}>
      <button type="submit" disabled={pending} className="rounded-md border p-2 hover:bg-gray-100">
        <span className="sr-only">Delete</span>
        <TrashIcon className="w-5" />
      </button>
    </form>
  );
}
