from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response

class CustomPagination(PageNumberPagination):
    page_size = 2
    page_query_param = 'pages'
    page_size_query_param = 'records'
    max_page_size = 10


    def get_paginated_response(self, data):
        return Response({
            'paginations': {
                'next': self.get_next_link(),
                'previous': self.get_previous_link(),
                'count': self.page.paginator.count,
                'total_page': self.page.paginator.num_pages,
            },
            'data': data,
        })
    
